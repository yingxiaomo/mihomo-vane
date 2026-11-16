package cachefile

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func TestSageDiagnosticsStoreIsDedicatedAndDurable(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	missing, err := cache.GetSageDiagnostics("missing")
	require.NoError(t, err)
	require.Nil(t, missing)

	key := "sage-diagnostics/v1/0123456789abcdef"
	payload := []byte(`{"schemaVersion":1,"group":"very-long-unicode-group-测试"}`)
	require.NoError(t, cache.SetSageDiagnostics(key, payload))

	for i := 0; i < 8; i++ {
		cache.SetStorage(string(rune('a'+i)), bytes.Repeat([]byte{byte(i)}, storageSizeLimit/8))
	}

	actual, err := cache.GetSageDiagnostics(key)
	require.NoError(t, err)
	require.Equal(t, payload, actual)
}

func TestSageDiagnosticsStoreReportsUnavailableAndOversize(t *testing.T) {
	cache := &CacheFile{}
	_, err := cache.GetSageDiagnostics("key")
	require.ErrorIs(t, err, ErrCacheUnavailable)
	require.ErrorIs(t, cache.SetSageDiagnostics("key", []byte("value")), ErrCacheUnavailable)

	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache.DB = db
	require.Error(t, cache.SetSageDiagnostics("key", make([]byte, sageDiagnosticsPayloadLimit+1)))
}

func TestSageDiagnosticsStoreIsLRUBounded(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	for i := 0; i <= sageDiagnosticsEntryLimit; i++ {
		stamp := i + 1
		if i == 1 {
			stamp = 1
		}
		updatedAt := time.Unix(int64(stamp), 0).UTC().Format(time.RFC3339Nano)
		payload := []byte(fmt.Sprintf("{%q:%q,%q:%d}", "updatedAt", updatedAt, "counter", i))
		require.NoError(t, cache.SetSageDiagnostics(fmt.Sprintf("key-%03d", i), payload))
	}

	oldest, err := cache.GetSageDiagnostics("key-000")
	require.NoError(t, err)
	require.Nil(t, oldest)
	newest, err := cache.GetSageDiagnostics(fmt.Sprintf("key-%03d", sageDiagnosticsEntryLimit))
	require.NoError(t, err)
	require.NotEmpty(t, newest)
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		require.Equal(t, sageDiagnosticsEntryLimit, tx.Bucket(bucketSageDiagnostics).Stats().KeyN)
		return nil
	}))
}

func TestSageDiagnosticsStorePrunesLegacyOversizedBucketOnUpdate(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSageDiagnostics)
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
	require.NoError(t, cache.SetSageDiagnostics("legacy-299", payload))

	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSageDiagnostics)
		require.Equal(t, sageDiagnosticsEntryLimit, bucket.Stats().KeyN)
		require.Nil(t, bucket.Get([]byte("legacy-000")))
		require.Equal(t, payload, bucket.Get([]byte("legacy-299")))
		return nil
	}))
}
