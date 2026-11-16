package outboundgroup

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestSageNamespaceNamesAndPrivacyIsolation(t *testing.T) {
	home := t.TempDir()
	useSagePriorHome(t, home)
	require.Equal(t, "sage-native-events-v1", sageNativeSourceSchema)
	require.Equal(t, "sage-prior-native-features-v1", sageNativeFeatureSchema)
	require.Equal(t, 1, SageLearningSchemaVersion)
	require.Equal(t, 2, SageDiagnosticsSchemaVersion)
	require.Equal(t, 2, sagePriorSchemaVersion)
	require.Contains(t, sageLearningStorageKey("test"), "sage-state-v1:")
	require.Contains(t, sageDiagnosticsStorageKey("test"), "sage-diag-v1:")
	spec, err := newSageNativeCollectorSpec(true, "", 0, 0, 0, 0)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, "sage-events"), spec.directory)
	oldKey := filepath.Join(home, "adaptive-native.key")
	sentinel := bytes.Repeat([]byte{0x42}, 32)
	require.NoError(t, os.WriteFile(oldKey, sentinel, 0600))
	key, id, err := sageNativePrivacyKey()
	require.NoError(t, err)
	require.Len(t, key, 32)
	require.NotEqual(t, sentinel, key)
	require.NotEmpty(t, id)
	again, againID, err := sageNativePrivacyKey()
	require.NoError(t, err)
	require.Equal(t, key, again)
	require.Equal(t, id, againID)
	old, err := os.ReadFile(oldKey)
	require.NoError(t, err)
	require.Equal(t, sentinel, old)
	// Recovery only owns the new product prefix; old live files must not be touched.
	oldOpen := filepath.Join(home, "adaptive-native-v1.old.1.1.jsonl.open")
	newOpen := filepath.Join(home, "sage-native-v1.new.1.1.jsonl.open")
	require.NoError(t, os.WriteFile(oldOpen, []byte("old-incomplete"), 0600))
	require.NoError(t, os.WriteFile(newOpen, []byte("{}\npartial"), 0600))
	require.NoError(t, recoverSageNativeOpenFiles(home))
	old, err = os.ReadFile(oldOpen)
	require.NoError(t, err)
	require.Equal(t, "old-incomplete", string(old))
	got, err := os.ReadFile(filepath.Join(home, "sage-native-v1.new.1.1.jsonl.recovered"))
	require.NoError(t, err)
	require.Equal(t, "{}\n", string(got))
}

func TestSagePriorRejectsLegacySchemas(t *testing.T) {
	for _, tc := range []struct{ field, value string }{{"source_schema", "adaptive-native-events-v1"}, {"feature_schema", "adaptive-prior-native-features-v1"}} {
		t.Run(tc.field, func(t *testing.T) {
			home := copySagePriorFixture(t)
			useSagePriorHome(t, home)
			path := filepath.Join(home, "SagePrior.json")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var manifest map[string]any
			require.NoError(t, json.Unmarshal(data, &manifest))
			manifest[tc.field] = tc.value
			data, err = json.Marshal(manifest)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, data, 0600))
			prior, err := loadSagePrior("SagePrior.json")
			require.Error(t, err)
			require.Nil(t, prior)
		})
	}
}
