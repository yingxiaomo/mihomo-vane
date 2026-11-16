package cachefile

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func TestVaneDiagnosticsStoreIsDedicatedAndDurable(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	missing, err := cache.GetVaneDiagnostics("missing")
	require.NoError(t, err)
	require.Nil(t, missing)

	key := "vane-diagnostics/v1/0123456789abcdef"
	payload := []byte(`{"schemaVersion":1,"group":"very-long-unicode-group-测试"}`)
	require.NoError(t, cache.SetVaneDiagnostics(key, payload))

	for i := 0; i < 8; i++ {
		cache.SetStorage(string(rune('a'+i)), bytes.Repeat([]byte{byte(i)}, storageSizeLimit/8))
	}

	actual, err := cache.GetVaneDiagnostics(key)
	require.NoError(t, err)
	require.Equal(t, payload, actual)
}

func TestVaneDiagnosticsStoreReportsUnavailableAndOversize(t *testing.T) {
	cache := &CacheFile{}
	_, err := cache.GetVaneDiagnostics("key")
	require.ErrorIs(t, err, ErrCacheUnavailable)
	require.ErrorIs(t, cache.SetVaneDiagnostics("key", []byte("value")), ErrCacheUnavailable)

	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache.DB = db
	require.Error(t, cache.SetVaneDiagnostics("key", make([]byte, vaneDiagnosticsPayloadLimit+1)))
}

func TestVaneDiagnosticsStoreIsLRUBounded(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	for i := 0; i <= vaneDiagnosticsEntryLimit; i++ {
		stamp := i + 1
		if i == 1 {
			stamp = 1
		}
		updatedAt := time.Unix(int64(stamp), 0).UTC().Format(time.RFC3339Nano)
		payload := []byte(fmt.Sprintf("{%q:%q,%q:%d}", "updatedAt", updatedAt, "counter", i))
		require.NoError(t, cache.SetVaneDiagnostics(fmt.Sprintf("key-%03d", i), payload))
	}

	oldest, err := cache.GetVaneDiagnostics("key-000")
	require.NoError(t, err)
	require.Nil(t, oldest)
	newest, err := cache.GetVaneDiagnostics(fmt.Sprintf("key-%03d", vaneDiagnosticsEntryLimit))
	require.NoError(t, err)
	require.NotEmpty(t, newest)
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		require.Equal(t, vaneDiagnosticsEntryLimit, tx.Bucket(bucketVaneDiagnostics).Stats().KeyN)
		return nil
	}))
}

func TestVaneDiagnosticsStorePrunesLegacyOversizedBucketOnUpdate(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketVaneDiagnostics)
		if err != nil {
			return err
		}
		for i := 0; i < 300; i++ {
			updatedAt := time.Unix(int64(i+1), 0).UTC().Format(time.RFC3339Nano)
			payload := []byte(fmt.Sprintf("{%q:%q,%q:%d}", "updatedAt", updatedAt, "counter", i))
			if err := bucket.Put([]byte(fmt.Sprintf("legacy-%03d", i)), payload); err != nil {
				return err
			}
		}
		return nil
	}))
	updatedAt := time.Unix(1_000, 0).UTC().Format(time.RFC3339Nano)
	payload := []byte(fmt.Sprintf("{%q:%q}", "updatedAt", updatedAt))
	require.NoError(t, cache.SetVaneDiagnostics("legacy-299", payload))

	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketVaneDiagnostics)
		require.Equal(t, vaneDiagnosticsEntryLimit, bucket.Stats().KeyN)
		require.Nil(t, bucket.Get([]byte("legacy-000")))
		require.Equal(t, payload, bucket.Get([]byte("legacy-299")))
		return nil
	}))
}
