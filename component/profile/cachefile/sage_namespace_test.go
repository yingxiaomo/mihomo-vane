package cachefile

import (
	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSageNamespacePreservesLegacyBuckets(t *testing.T) {
	path := t.TempDir() + "/cache.db"
	db, err := bbolt.Open(path, 0600, nil)
	require.NoError(t, err)
	old := []string{"adaptiveState", "adaptiveStateMeta", "adaptiveDiagnostics", "pld:"}
	key := "same-key"
	sentinel := []byte("legacy-must-remain-byte-identical")
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		for _, name := range old {
			b, e := tx.CreateBucketIfNotExists([]byte(name))
			if e != nil {
				return e
			}
			if e = b.Put([]byte(key), sentinel); e != nil {
				return e
			}
		}
		return nil
	}))
	cache := &CacheFile{DB: db}
	state, err := cache.GetSageState(key)
	require.NoError(t, err)
	require.Nil(t, state)
	diag, err := cache.GetSageDiagnostics(key)
	require.NoError(t, err)
	require.Nil(t, diag)
	_, lease, err := cache.GetSageStateWithToken(key)
	require.NoError(t, err)
	require.Len(t, lease, 16)
	payload := []byte(`{"schemaVersion":1,"updatedAt":"2026-11-15T00:00:00Z"}`)
	_, err = cache.CompareAndSwapSageState(key, lease, payload)
	require.NoError(t, err)
	require.NoError(t, cache.SetSageDiagnostics(key, []byte(`{"schemaVersion":2,"updatedAt":"2026-11-15T00:00:00Z"}`)))
	require.NoError(t, db.Close())
	db, err = bbolt.Open(path, 0600, nil)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		for _, name := range old {
			b := tx.Bucket([]byte(name))
			require.NotNil(t, b)
			require.Equal(t, sentinel, []byte(b.Get([]byte(key))))
			require.Equal(t, 1, b.Stats().KeyN)
		}
		for _, name := range []string{"sageState", "sageStateMeta", "sageDiagnostics"} {
			require.NotNil(t, tx.Bucket([]byte(name)))
		}
		require.Equal(t, payload, []byte(tx.Bucket([]byte("sageState")).Get([]byte(key))))
		return nil
	}))
}
