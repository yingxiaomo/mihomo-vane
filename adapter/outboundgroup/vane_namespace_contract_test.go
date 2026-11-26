package outboundgroup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestVaneNamespaceNamesAndPrivacyIsolation(t *testing.T) {
	previousProduct := "sa" + "ge"
	home := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	require.Equal(t, "vane-native-events-v1", vaneNativeSourceSchema)
	require.Equal(t, "vane-native-features-v1", vaneNativeFeatureSchema)
	require.Equal(t, 3, VaneLearningSchemaVersion)
	require.Equal(t, 3, VaneDiagnosticsSchemaVersion)
	require.Contains(t, vaneLearningStorageKey("test"), "vane-state-v1:")
	spec, err := newVaneNativeCollectorSpec(true, "", 0, 0, 0, 0)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, "vane-events"), spec.directory)
	oldKey := filepath.Join(home, previousProduct+"-native.key")
	sentinel := bytes.Repeat([]byte{0x42}, 32)
	require.NoError(t, os.WriteFile(oldKey, sentinel, 0600))
	key, id, err := vaneNativePrivacyKey()
	require.NoError(t, err)
	require.Len(t, key, 32)
	require.NotEqual(t, sentinel, key)
	require.NotEmpty(t, id)
	again, againID, err := vaneNativePrivacyKey()
	require.NoError(t, err)
	require.Equal(t, key, again)
	require.Equal(t, id, againID)
	old, err := os.ReadFile(oldKey)
	require.NoError(t, err)
	require.Equal(t, sentinel, old)
	// Recovery owns only the new product prefix; previous live files stay untouched.
	oldOpen := filepath.Join(home, previousProduct+"-native-v1.old.1.1.jsonl.open")
	newOpen := filepath.Join(home, "vane-native-v1.new.1.1.jsonl.open")
	require.NoError(t, os.WriteFile(oldOpen, []byte("old-incomplete"), 0600))
	require.NoError(t, os.WriteFile(newOpen, []byte("{}\npartial"), 0600))
	require.NoError(t, recoverVaneNativeOpenFiles(home))
	old, err = os.ReadFile(oldOpen)
	require.NoError(t, err)
	require.Equal(t, "old-incomplete", string(old))
	got, err := os.ReadFile(filepath.Join(home, "vane-native-v1.new.1.1.jsonl.recovered"))
	require.NoError(t, err)
	require.Equal(t, "{}\n", string(got))
}
