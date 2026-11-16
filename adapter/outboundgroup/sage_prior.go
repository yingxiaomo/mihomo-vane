package outboundgroup

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vernesong/leaves"

	C "github.com/metacubex/mihomo/constant"
)

const (
	sagePriorSchemaVersion        = 2
	sagePriorFeatureSchema        = sageNativeFeatureSchema
	sagePriorSourceSchema         = sageNativeSourceSchema
	sagePriorMaxManifest          = 1 << 20
	sagePriorMaxModel             = 64 << 20
	sagePriorMaxConfidence        = 0.35
	sagePriorMinTrainSamples      = 20
	sagePriorMinSplitSamples      = 5
	sagePriorMinConfidenceSamples = 20
)

var sagePriorFeatureOrder = []string{
	"is_udp",
	"is_tcp",
	"port_log",
	"asn_hash",
	"host_hash",
	"ip_hash",
	"group_hash",
	"node_type",
}

type sagePriorDimensionSpec struct {
	Model              string  `json:"model"`
	SHA256             string  `json:"sha256"`
	Unit               string  `json:"unit"`
	Confidence         float64 `json:"confidence"`
	TrainSamples       int     `json:"train_samples"`
	EarlyStopSamples   int     `json:"early_stop_samples"`
	CalibrationSamples int     `json:"calibration_samples"`
	ValidationSamples  int     `json:"validation_samples"`
	ValidationMetric   string  `json:"validation_metric"`
	ValidationError    float64 `json:"validation_error"`
	BaselineError      float64 `json:"baseline_error"`
	OutputTransform    string  `json:"output_transform"`
	CalibrationScale   float64 `json:"calibration_scale"`
	CalibrationBias    float64 `json:"calibration_bias"`
}

type sagePriorManifest struct {
	SchemaVersion          int                               `json:"schema_version"`
	FeatureSchema          string                            `json:"feature_schema"`
	SourceSchema           string                            `json:"source_schema"`
	FeatureOrder           []string                          `json:"feature_order"`
	GeneratedFromEventUnix int64                             `json:"generated_from_event_unix"`
	MaxPriorConfidence     float64                           `json:"max_prior_confidence"`
	Dimensions             map[string]sagePriorDimensionSpec `json:"dimensions"`
}

type sagePriorDimension struct {
	model      *leaves.Ensemble
	confidence float64
	transform  string
	scale      float64
	bias       float64
}

type sagePriorModel struct {
	path                   string
	connect                sagePriorDimension
	response               sagePriorDimension
	throughput             sagePriorDimension
	failure                sagePriorDimension
	featureSchema          string
	sourceSchema           string
	generatedFromEventUnix int64
	manifestSHA256         string
	modelSHA256            map[string]string
}

type sagePriorEstimate struct {
	value      float64
	confidence float64
	valid      bool
}

type sagePriorSnapshot struct {
	connect    sagePriorEstimate
	response   sagePriorEstimate
	throughput sagePriorEstimate
	failure    sagePriorEstimate
}

func loadSagePrior(path string) (*sagePriorModel, error) {
	resolved := C.Path.Resolve(path)
	if !C.Path.IsSafePath(resolved) {
		return nil, C.Path.ErrNotSafePath(resolved)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat sage prior manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > sagePriorMaxManifest {
		return nil, fmt.Errorf("sage prior manifest has invalid size %d", info.Size())
	}
	payload, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read sage prior manifest: %w", err)
	}
	var manifest sagePriorManifest
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode sage prior manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode sage prior manifest: trailing data")
	}
	if manifest.SchemaVersion != sagePriorSchemaVersion {
		return nil, fmt.Errorf("unsupported sage prior schema %d", manifest.SchemaVersion)
	}
	if manifest.FeatureSchema != sagePriorFeatureSchema {
		return nil, fmt.Errorf("unsupported sage prior feature schema %q", manifest.FeatureSchema)
	}
	if manifest.SourceSchema != sagePriorSourceSchema {
		return nil, fmt.Errorf("unsupported sage prior source schema %q", manifest.SourceSchema)
	}
	if len(manifest.FeatureOrder) != len(sagePriorFeatureOrder) {
		return nil, fmt.Errorf("sage prior feature count %d, want %d", len(manifest.FeatureOrder), len(sagePriorFeatureOrder))
	}
	for index, feature := range sagePriorFeatureOrder {
		if manifest.FeatureOrder[index] != feature {
			return nil, fmt.Errorf("sage prior feature %d is %q, want %q", index, manifest.FeatureOrder[index], feature)
		}
	}
	if manifest.GeneratedFromEventUnix <= 0 {
		return nil, fmt.Errorf("sage prior source event timestamp is invalid")
	}
	if !sagePriorFinite(manifest.MaxPriorConfidence) || manifest.MaxPriorConfidence < 0 || manifest.MaxPriorConfidence > sagePriorMaxConfidence {
		return nil, fmt.Errorf("sage prior confidence cap is invalid")
	}

	expectedUnits := map[string]string{
		"connect":    "log_milliseconds",
		"response":   "log_milliseconds",
		"throughput": "log_bits_per_second",
		"failure":    "probability",
	}
	expectedMetrics := map[string]string{
		"connect": "mae_log", "response": "mae_log",
		"throughput": "mae_log", "failure": "brier",
	}
	manifestDigest := sha256.Sum256(payload)
	loaded := &sagePriorModel{
		path:                   resolved,
		featureSchema:          manifest.FeatureSchema,
		sourceSchema:           manifest.SourceSchema,
		generatedFromEventUnix: manifest.GeneratedFromEventUnix,
		manifestSHA256:         hex.EncodeToString(manifestDigest[:]),
		modelSHA256:            make(map[string]string, 4),
	}
	for _, name := range []string{"connect", "response", "throughput", "failure"} {
		spec, ok := manifest.Dimensions[name]
		if !ok {
			return nil, fmt.Errorf("sage prior dimension %q is missing", name)
		}
		if spec.Unit != expectedUnits[name] {
			return nil, fmt.Errorf("sage prior dimension %q unit %q is invalid", name, spec.Unit)
		}
		if !sagePriorFinite(spec.Confidence) || spec.Confidence < 0 || spec.Confidence > manifest.MaxPriorConfidence || spec.Confidence > sagePriorMaxConfidence {
			return nil, fmt.Errorf("sage prior dimension %q confidence is invalid", name)
		}
		if spec.TrainSamples < sagePriorMinTrainSamples || spec.EarlyStopSamples < sagePriorMinSplitSamples || spec.CalibrationSamples < sagePriorMinSplitSamples || spec.ValidationSamples < sagePriorMinSplitSamples || !sagePriorFinite(spec.ValidationError) || spec.ValidationError < 0 || !sagePriorFinite(spec.BaselineError) || spec.BaselineError < 0 || !sagePriorFinite(spec.CalibrationScale) || !sagePriorFinite(spec.CalibrationBias) {
			return nil, fmt.Errorf("sage prior dimension %q validation metadata is invalid", name)
		}
		if spec.ValidationMetric != expectedMetrics[name] {
			return nil, fmt.Errorf("sage prior dimension %q validation metric %q is invalid", name, spec.ValidationMetric)
		}
		if spec.Confidence > 0 && spec.ValidationSamples < sagePriorMinConfidenceSamples {
			return nil, fmt.Errorf("sage prior dimension %q confidence lacks independent validation samples", name)
		}
		justifiedConfidence := 0.0
		if spec.BaselineError > 1e-12 {
			justifiedConfidence = sageClamp(1-spec.ValidationError/spec.BaselineError, 0, sagePriorMaxConfidence)
		}
		if spec.Confidence > justifiedConfidence+1e-6 {
			return nil, fmt.Errorf("sage prior dimension %q confidence is not justified by validation", name)
		}
		if (name == "failure" && (spec.OutputTransform != "sigmoid" || spec.CalibrationScale <= 0)) || (name != "failure" && (spec.OutputTransform != "identity" || spec.CalibrationScale != 1 || spec.CalibrationBias != 0)) {
			return nil, fmt.Errorf("sage prior dimension %q output transform is invalid", name)
		}
		dimension, err := loadSagePriorDimension(filepath.Dir(resolved), name, spec)
		if err != nil {
			return nil, fmt.Errorf("load sage prior dimension %q: %w", name, err)
		}
		switch name {
		case "connect":
			loaded.connect = dimension
		case "response":
			loaded.response = dimension
		case "throughput":
			loaded.throughput = dimension
		case "failure":
			loaded.failure = dimension
		}
		loaded.modelSHA256[name] = strings.ToLower(spec.SHA256)
	}
	if len(manifest.Dimensions) != 4 {
		return nil, fmt.Errorf("sage prior manifest has unexpected dimensions")
	}
	return loaded, nil
}

func loadSagePriorDimension(directory, name string, spec sagePriorDimensionSpec) (sagePriorDimension, error) {
	if spec.Model == "" || filepath.Base(spec.Model) != spec.Model {
		return sagePriorDimension{}, fmt.Errorf("model path must be one file in the manifest directory")
	}
	if len(spec.SHA256) != sha256.Size*2 {
		return sagePriorDimension{}, fmt.Errorf("model sha256 has invalid length")
	}
	modelPath := filepath.Join(directory, spec.Model)
	if !C.Path.IsSafePath(modelPath) {
		return sagePriorDimension{}, C.Path.ErrNotSafePath(modelPath)
	}
	info, err := os.Stat(modelPath)
	if err != nil {
		return sagePriorDimension{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > sagePriorMaxModel {
		return sagePriorDimension{}, fmt.Errorf("model has invalid size %d", info.Size())
	}
	payload, err := os.ReadFile(modelPath)
	if err != nil {
		return sagePriorDimension{}, err
	}
	if int64(len(payload)) != info.Size() || len(payload) == 0 || len(payload) > sagePriorMaxModel {
		return sagePriorDimension{}, fmt.Errorf("model changed while being read")
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), spec.SHA256) {
		return sagePriorDimension{}, fmt.Errorf("model sha256 mismatch")
	}
	if err := validateSagePriorModelABI(payload, name); err != nil {
		return sagePriorDimension{}, err
	}
	model, err := parseSagePriorModel(payload)
	if err != nil {
		return sagePriorDimension{}, err
	}
	if model.NFeatures() != len(sagePriorFeatureOrder) {
		return sagePriorDimension{}, fmt.Errorf("model feature count %d, want %d", model.NFeatures(), len(sagePriorFeatureOrder))
	}
	if model.NOutputGroups() != 1 {
		return sagePriorDimension{}, fmt.Errorf("model output groups %d, want 1", model.NOutputGroups())
	}
	return sagePriorDimension{
		model: model, confidence: spec.Confidence,
		transform: spec.OutputTransform, scale: spec.CalibrationScale, bias: spec.CalibrationBias,
	}, nil
}

func parseSagePriorModel(payload []byte) (model *leaves.Ensemble, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			model = nil
			err = fmt.Errorf("LightGBM parser panic: %v", recovered)
		}
	}()
	return leaves.LGEnsembleFromReader(bufio.NewReader(bytes.NewReader(payload)), false)
}

func validateSagePriorModelABI(payload []byte, name string) error {
	objective := sagePriorModelHeader(payload, "objective=")
	if (name == "failure" && !strings.HasPrefix(objective, "binary ")) || (name != "failure" && !strings.HasPrefix(objective, "regression")) {
		return fmt.Errorf("model objective %q is invalid for %s", objective, name)
	}
	featureNames := strings.Fields(sagePriorModelHeader(payload, "feature_names="))
	if len(featureNames) != len(sagePriorFeatureOrder) {
		return fmt.Errorf("model feature names count %d, want %d", len(featureNames), len(sagePriorFeatureOrder))
	}
	for index, feature := range sagePriorFeatureOrder {
		if featureNames[index] != feature {
			return fmt.Errorf("model feature name %d is %q, want %q", index, featureNames[index], feature)
		}
	}
	return nil
}

func sagePriorModelHeader(payload []byte, prefix string) string {
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte(prefix)) {
			return strings.TrimSpace(string(line[len(prefix):]))
		}
	}
	return ""
}

func (p *sagePriorModel) predict(metadata *C.Metadata, proxy C.Proxy, group, testURL string, now time.Time) sagePriorSnapshot {
	if p == nil || metadata == nil || proxy == nil {
		return sagePriorSnapshot{}
	}
	features := prepareSagePriorFeatures(metadata, proxy, group, testURL, now)
	return sagePriorSnapshot{
		connect:    predictSagePriorDimension(p.connect, features, math.Log(1), math.Log(30_000)),
		response:   predictSagePriorDimension(p.response, features, math.Log(1), math.Log(30_000)),
		throughput: predictSagePriorDimension(p.throughput, features, math.Log(8_192), math.Log(1_000_000_000)),
		failure:    predictSagePriorDimension(p.failure, features, 0, 1),
	}
}

func predictSagePriorDimension(dimension sagePriorDimension, features []float64, minimum, maximum float64) (result sagePriorEstimate) {
	if dimension.model == nil || dimension.confidence <= 0 || len(features) != len(sagePriorFeatureOrder) {
		return sagePriorEstimate{}
	}
	var raw float64
	ok := true
	func() {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		raw = dimension.model.PredictSingle(features, 0)
	}()
	if !ok || !sagePriorFinite(raw) {
		return sagePriorEstimate{}
	}
	raw = dimension.scale*raw + dimension.bias
	if dimension.transform == "sigmoid" {
		if raw >= 0 {
			raw = 1 / (1 + math.Exp(-raw))
		} else {
			exponential := math.Exp(raw)
			raw = exponential / (1 + exponential)
		}
	}
	if !sagePriorFinite(raw) {
		return sagePriorEstimate{}
	}
	return sagePriorEstimate{
		value:      sageClamp(raw, minimum, maximum),
		confidence: dimension.confidence,
		valid:      true,
	}
}

func prepareSagePriorFeatures(metadata *C.Metadata, proxy C.Proxy, group, _ string, _ time.Time) []float64 {
	isUDP := 0.0
	if metadata.NetWork == C.UDP {
		isUDP = 1
	}

	host := strings.TrimSpace(metadata.Host)
	asn := strings.TrimSpace(metadata.DstIPASN)
	ip := ""
	if metadata.DstIP.IsValid() {
		ip = metadata.DstIP.String()
	}
	return []float64{
		isUDP,
		1 - isUDP,
		math.Log1p(float64(metadata.DstPort)),
		sagePriorHash(asn, 500),
		sagePriorHash(host, 1000),
		sagePriorHash(ip, 10000),
		sagePriorHash(group, 200),
		float64(proxy.Type()),
	}
}

func sagePriorHash(text string, buckets uint32) float64 {
	if text == "" || buckets == 0 {
		return 0
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(text))
	return float64(hash.Sum32()%buckets + 1)
}

func sagePriorFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
