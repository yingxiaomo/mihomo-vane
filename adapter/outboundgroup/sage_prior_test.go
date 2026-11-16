package outboundgroup

import (
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func useSagePriorHome(t *testing.T, home string) {
	t.Helper()
	old := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(old) })
}

func copySagePriorFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("testdata", "sage_prior"))
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, entry.IsDir())
		name := entry.Name()
		payload, err := os.ReadFile(filepath.Join("testdata", "sage_prior", name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(home, name), payload, 0o600))
	}
	return home
}

func sagePriorMetadata() *C.Metadata {
	return &C.Metadata{
		NetWork:   C.TCP,
		DstIP:     netip.MustParseAddr("1.1.1.1"),
		DstIPASN:  "AS13335 Cloudflare",
		DstPort:   443,
		Host:      "r1.googlevideo.com",
		SniffHost: ".googlevideo.com",
	}
}

func TestSagePriorFeatureParity(t *testing.T) {
	proxy := newSageTestProxy("节点A", true, true)
	proxy.delay = 80
	features := prepareSagePriorFeatures(
		sagePriorMetadata(), proxy, "sage-main", C.DefaultTestURL,
		time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
	)
	require.Len(t, features, 8)
	require.InDelta(t, 0, features[0], 1e-12)
	require.InDelta(t, 1, features[1], 1e-12)
	require.InDelta(t, 6.095824562432225, features[2], 1e-12)
	// FNV-1a("sage-main") % 200 + 1 = 54; only the renamed fixture input changed.
	require.Equal(t, []float64{66, 464, 706, 54}, features[3:7])
	require.Equal(t, float64(proxy.Type()), features[7])

	// Node name and persistent identity are deliberately absent. A replacement
	// can share semantic priors, but never identity-specific online evidence.
	replacement := newSageTestProxy("另一个名字", true, true)
	replacement.identity = "replacement-config"
	replacement.delay = proxy.delay
	require.Equal(t, features, prepareSagePriorFeatures(
		sagePriorMetadata(), replacement, "sage-main", C.DefaultTestURL,
		time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
	))
}

func TestSagePriorBundleLoadsAndPredictsIndependentDimensions(t *testing.T) {
	home := copySagePriorFixture(t)
	useSagePriorHome(t, home)
	prior, err := loadSagePrior("SagePrior.json")
	require.NoError(t, err)

	proxy := newSageTestProxy("alpha", true, true)
	proxy.delay = 80
	prediction := prior.predict(
		sagePriorMetadata(), proxy, "sage-main", C.DefaultTestURL,
		time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
	)
	require.True(t, prediction.connect.valid)
	require.True(t, prediction.response.valid)
	require.True(t, prediction.throughput.valid)
	require.True(t, prediction.failure.valid)
	require.InDelta(t, sagePriorMaxConfidence, prediction.connect.confidence, 1e-12)
	require.InDelta(t, sagePriorMaxConfidence, prediction.response.confidence, 1e-12)
	require.InDelta(t, sagePriorMaxConfidence, prediction.throughput.confidence, 1e-12)
	require.InDelta(t, sagePriorMaxConfidence, prediction.failure.confidence, 1e-12)
	require.GreaterOrEqual(t, prediction.connect.value, math.Log(1))
	require.LessOrEqual(t, prediction.connect.value, math.Log(30_000))
	require.GreaterOrEqual(t, prediction.throughput.value, math.Log(8_192))
	require.LessOrEqual(t, prediction.throughput.value, math.Log(1_000_000_000))
	features := prepareSagePriorFeatures(sagePriorMetadata(), proxy, "sage-main", C.DefaultTestURL, time.Time{})
	failureDimension := prior.failure
	failureDimension.confidence = sagePriorMaxConfidence
	failurePrediction := predictSagePriorDimension(failureDimension, features, 0, 1)
	require.True(t, failurePrediction.valid)
	require.GreaterOrEqual(t, failurePrediction.value, 0.0)
	require.LessOrEqual(t, failurePrediction.value, 1.0)
	require.NotEqual(t, prediction.connect.value, prediction.throughput.value,
		"the dimensional contract must not duplicate one scalar into every metric")

	group, _ := newSageGroupForTest(newSageConnTestClock(), sageDefaultMaxStates, sageDefaultStateTTL, proxy)
	group.prior = prior
	config := group.SageDiagnostics().Config
	require.True(t, config.PriorEnabled)
	require.InDelta(t, sagePriorMaxConfidence, config.PriorConnectConfidence, 1e-12)
	require.InDelta(t, sagePriorMaxConfidence, config.PriorResponseConfidence, 1e-12)
	require.InDelta(t, sagePriorMaxConfidence, config.PriorThroughputConfidence, 1e-12)
	require.InDelta(t, sagePriorMaxConfidence, config.PriorFailureConfidence, 1e-12)
	require.Equal(t, sagePriorFeatureSchema, config.PriorFeatureSchema)
	require.Equal(t, sagePriorSourceSchema, config.PriorSourceSchema)
	require.Len(t, config.PriorManifestSHA256, 64)
	require.Len(t, config.PriorFailureSHA256, 64)
}

func TestSagePriorBundleRejectsTamperingAndPathTraversal(t *testing.T) {
	home := copySagePriorFixture(t)
	useSagePriorHome(t, home)
	manifestPayload, err := os.ReadFile(filepath.Join(home, "SagePrior.json"))
	require.NoError(t, err)
	var fixtureManifest sagePriorManifest
	require.NoError(t, json.Unmarshal(manifestPayload, &fixtureManifest))
	modelPath := filepath.Join(home, fixtureManifest.Dimensions["connect"].Model)
	file, err := os.OpenFile(modelPath, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteString("tampered")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	_, err = loadSagePrior("SagePrior.json")
	require.ErrorContains(t, err, "sha256 mismatch")

	home = copySagePriorFixture(t)
	useSagePriorHome(t, home)
	manifestPath := filepath.Join(home, "SagePrior.json")
	payload, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(payload, &manifest))
	dimensions := manifest["dimensions"].(map[string]any)
	dimensions["connect"].(map[string]any)["model"] = "../SagePrior-connect.lgb"
	payload, err = json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, payload, 0o600))
	_, err = loadSagePrior("SagePrior.json")
	require.ErrorContains(t, err, "manifest directory")

	home = copySagePriorFixture(t)
	useSagePriorHome(t, home)
	manifestPath = filepath.Join(home, "SagePrior.json")
	payload, err = os.ReadFile(manifestPath)
	require.NoError(t, err)
	manifest = map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &manifest))
	dimensions = manifest["dimensions"].(map[string]any)
	dimensions["failure"].(map[string]any)["confidence"] = 0.35
	dimensions["failure"].(map[string]any)["validation_error"] = dimensions["failure"].(map[string]any)["baseline_error"].(float64) * 2
	payload, err = json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, payload, 0o600))
	_, err = loadSagePrior("SagePrior.json")
	require.ErrorContains(t, err, "confidence is not justified")

	home = copySagePriorFixture(t)
	useSagePriorHome(t, home)
	manifestPath = filepath.Join(home, "SagePrior.json")
	payload, err = os.ReadFile(manifestPath)
	require.NoError(t, err)
	manifest = map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &manifest))
	dimension := manifest["dimensions"].(map[string]any)["connect"].(map[string]any)
	dimension["train_samples"] = 0
	dimension["validation_error"] = -1
	dimension["validation_metric"] = "invented"
	payload, err = json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, payload, 0o600))
	_, err = loadSagePrior("SagePrior.json")
	require.ErrorContains(t, err, "validation metadata is invalid")
}

func TestSagePriorMalformedModelCannotPanicLoader(t *testing.T) {
	payload := []byte("tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nlabel_index=0\nmax_feature_idx=7\nobjective=regression\nfeature_names=is_udp is_tcp port_log asn_hash host_hash ip_hash group_hash node_type\nfeature_infos=none none none none none none none none\ntree_sizes=1\n\nTree=0\nnum_leaves=2\nnum_cat=0\nsplit_feature=0\ndecision_type=0\nthreshold=0\nleft_child=1\nright_child=-1\nleaf_value=0 1\nis_linear=0\nshrinkage=1\n\n\nend of trees\n")
	require.NoError(t, validateSagePriorModelABI(payload, "connect"))
	model, err := parseSagePriorModel(payload)
	require.Nil(t, model)
	require.ErrorContains(t, err, "parser panic")
}

func TestSagePriorExternalBundle(t *testing.T) {
	path := os.Getenv("SAGE_PRIOR_BUNDLE")
	if path == "" {
		t.Skip("SAGE_PRIOR_BUNDLE is not set")
	}
	absolute, err := filepath.Abs(path)
	require.NoError(t, err)
	useSagePriorHome(t, filepath.Dir(absolute))
	prior, err := loadSagePrior(filepath.Base(absolute))
	require.NoError(t, err)
	require.Equal(t, sagePriorFeatureSchema, prior.featureSchema)
	require.Equal(t, sagePriorSourceSchema, prior.sourceSchema)
	require.Len(t, prior.manifestSHA256, 64)
}

func TestSagePriorFusionNeverOverridesFullOnlineEvidence(t *testing.T) {
	observed := sageMetricEstimate{value: math.Log(100), confidence: 1, valid: true}
	prior := sagePriorEstimate{value: math.Log(30_000), confidence: 0.35, valid: true}
	withPrior := sageMetricCostWithPrior(observed, sageMetricConnect, prior, func(value float64) float64 {
		return sageLatencyCost(value, 50, 1500)
	})
	withoutPrior := sageMetricCost(observed, sageMetricConnect, func(value float64) float64 {
		return sageLatencyCost(value, 50, 1500)
	})
	require.InDelta(t, withoutPrior, withPrior, 1e-12)

	cold := sageMetricCostWithPrior(sageMetricEstimate{}, sageMetricFailure,
		sagePriorEstimate{value: 1, confidence: 1, valid: true},
		func(value float64) float64 { return sageClamp(value, 0, 1) },
	)
	missing := sageSpec(sageMetricFailure).missingCost
	require.InDelta(t, sagePriorMaxConfidence+(1-sagePriorMaxConfidence)*missing, cold, 1e-12)
}

func TestSagePriorIsExplicitAndOldConfigRemainsOnlineOnly(t *testing.T) {
	fallback := newSageTestProxy("fallback", true, false)
	group, err := NewSage(GroupCommonOption{Name: "sage"}, SageOption{}, fallback, nil)
	require.NoError(t, err)
	require.Nil(t, group.prior)

	home := t.TempDir()
	useSagePriorHome(t, home)
	_, err = NewSage(GroupCommonOption{Name: "sage"}, SageOption{PriorModel: "missing.json"}, fallback, nil)
	require.ErrorContains(t, err, "sage prior model")
}
