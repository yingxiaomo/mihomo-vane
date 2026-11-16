package cachefile

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func TestSageStateStoreIsDedicatedAndDurable(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	missing, err := cache.GetSageState("missing")
	require.NoError(t, err)
	require.Nil(t, missing)

	payload := []byte(`{"schemaVersion":1,"group":"sage","updatedAt":"2026-11-14T00:00:00Z"}`)
	require.NoError(t, cache.SetSageState("sage-state-v1:key", payload))
	require.NoError(t, cache.SetSageDiagnostics("sage-state-v1:key", []byte("diagnostics")))

	actual, err := cache.GetSageState("sage-state-v1:key")
	require.NoError(t, err)
	require.Equal(t, payload, actual)
	diagnostics, err := cache.GetSageDiagnostics("sage-state-v1:key")
	require.NoError(t, err)
	require.Equal(t, []byte("diagnostics"), diagnostics)
}

func TestSageStateStoreReportsUnavailableAndOversize(t *testing.T) {
	cache := &CacheFile{}
	_, err := cache.GetSageState("key")
	require.ErrorIs(t, err, ErrCacheUnavailable)
	require.ErrorIs(t, cache.SetSageState("key", []byte("value")), ErrCacheUnavailable)

	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache.DB = db
	require.Error(t, cache.SetSageState("key", make([]byte, sageStatePayloadLimit+1)))
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSageState)
		if err != nil {
			return err
		}
		return bucket.Put([]byte("legacy-oversize"), make([]byte, sageStatePayloadLimit+1))
	}))
	_, token, err := cache.GetSageStateWithToken("legacy-oversize")
	require.ErrorIs(t, err, ErrSageStatePayloadTooLarge)
	require.Len(t, token, sageStateTokenSize)
	replacement := []byte(`{"updatedAt":"2026-11-14T00:00:00Z","revision":1}`)
	_, err = cache.CompareAndSwapSageState("legacy-oversize", token, replacement)
	require.NoError(t, err)
	actual, err := cache.GetSageState("legacy-oversize")
	require.NoError(t, err)
	require.Equal(t, replacement, actual)
}

func TestSageStateOversizedFutureSchemaCannotBeDowngraded(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	payload := append([]byte(`{"schemaVersion":2,"padding":"`), bytes.Repeat([]byte{'x'}, sageStatePayloadLimit)...)
	payload = append(payload, []byte(`"}`)...)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, createErr := tx.CreateBucketIfNotExists(bucketSageState)
		if createErr != nil {
			return createErr
		}
		return bucket.Put([]byte("future"), payload)
	}))

	_, token, err := cache.GetSageStateWithToken("future")
	require.ErrorIs(t, err, ErrSageStateIncompatibleSchema)
	require.Len(t, token, sageStateTokenSize)
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		require.Equal(t, payload, []byte(tx.Bucket(bucketSageState).Get([]byte("future"))))
		return nil
	}))
}

func TestSageStateFreshLeasesOutliveLegacyRetentionEntries(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		meta, createErr := tx.CreateBucketIfNotExists(bucketSageStateMeta)
		if createErr != nil {
			return createErr
		}
		for i := 0; i < sageStateEntryLimit-1; i++ {
			if putErr := meta.Put([]byte(fmt.Sprintf("sage-state-v1:stale-%03d", i)), bytes.Repeat([]byte{byte(i)}, sageStateTokenSize)); putErr != nil {
				return putErr
			}
		}
		return nil
	}))

	_, tokenA, err := cache.GetSageStateWithToken("sage-state-v1:--fresh-a")
	require.NoError(t, err)
	_, tokenB, err := cache.GetSageStateWithToken("sage-state-v1:--fresh-b")
	require.NoError(t, err)
	_, err = cache.CompareAndSwapSageState("sage-state-v1:--fresh-a", tokenA, []byte(`{"schemaVersion":1,"updatedAt":"2026-11-15T00:00:00Z"}`))
	require.NoError(t, err, "a fresh active lease must be retained ahead of legacy zero-time leases")
	_, err = cache.CompareAndSwapSageState("sage-state-v1:--fresh-b", tokenB, []byte(`{"schemaVersion":1,"updatedAt":"2026-11-15T00:00:01Z"}`))
	require.NoError(t, err)
}

func TestSageStateStorePrunesLegacyOversizedBucketOnEverySave(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSageState)
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
	require.NoError(t, cache.SetSageState("legacy-299", payload))

	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSageState)
		require.Equal(t, sageStateEntryLimit, bucket.Stats().KeyN)
		require.Nil(t, bucket.Get([]byte("legacy-000")))
		require.Equal(t, payload, bucket.Get([]byte("legacy-299")))
		return nil
	}))
}

func TestSageStateCompareAndSwapRejectsStaleAndAbsentRace(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	missing, absentToken, err := cache.GetSageStateWithToken("key")
	require.NoError(t, err)
	require.Nil(t, missing)
	require.Len(t, absentToken, sageStateTokenSize)

	first := []byte(`{"updatedAt":"2026-11-14T00:00:00Z","revision":1}`)
	firstToken, err := cache.CompareAndSwapSageState("key", absentToken, first)
	require.NoError(t, err)
	require.Len(t, firstToken, sageStateTokenSize)

	_, err = cache.CompareAndSwapSageState("key", nil, []byte(`{"revision":0}`))
	require.ErrorIs(t, err, ErrSageStateConflict, "an absent-at-load writer must not overwrite a newly created row")

	second := []byte(`{"updatedAt":"2026-11-14T00:00:01Z","revision":2}`)
	secondToken, err := cache.CompareAndSwapSageState("key", firstToken, second)
	require.NoError(t, err)
	require.NotEqual(t, firstToken, secondToken)

	_, err = cache.CompareAndSwapSageState("key", firstToken, []byte(`{"revision":1}`))
	require.ErrorIs(t, err, ErrSageStateConflict, "a delayed old writer must not replace the newer revision")
	actual, actualToken, err := cache.GetSageStateWithToken("key")
	require.NoError(t, err)
	require.Equal(t, second, actual)
	require.NotEqual(t, secondToken, actualToken, "opening a new writer lease must fence the previous writer")
	_, err = cache.CompareAndSwapSageState("key", secondToken, []byte(`{"revision":3}`))
	require.ErrorIs(t, err, ErrSageStateConflict, "opening alone must fence the previous owner before the new owner saves")

	backToFirstToken, err := cache.CompareAndSwapSageState("key", actualToken, first)
	require.NoError(t, err)
	require.NotEqual(t, firstToken, backToFirstToken, "A-B-A payload cycles must still rotate the writer fence")
	_, err = cache.CompareAndSwapSageState("key", firstToken, []byte(`{"revision":99}`))
	require.ErrorIs(t, err, ErrSageStateConflict, "an old A writer must stay fenced after an A-B-A cycle")
}

func TestSageStateLegacyPruneSurvivesReopenAndPreservesOtherBuckets(t *testing.T) {
	path := t.TempDir() + "/cache.db"
	db, err := bbolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	cache := &CacheFile{DB: db}
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		selected, err := tx.CreateBucketIfNotExists(bucketSelected)
		if err != nil {
			return err
		}
		if err := selected.Put([]byte("group"), []byte("node")); err != nil {
			return err
		}
		storage, err := tx.CreateBucketIfNotExists(bucketStorage)
		if err != nil {
			return err
		}
		if err := storage.Put([]byte("unrelated"), []byte("preserved")); err != nil {
			return err
		}
		sage, err := tx.CreateBucketIfNotExists(bucketSageState)
		if err != nil {
			return err
		}
		for i := 0; i < 300; i++ {
			payload := []byte(fmt.Sprintf(`{"updatedAt":%q}`, time.Unix(int64(i+1), 0).UTC().Format(time.RFC3339Nano)))
			if err := sage.Put([]byte(fmt.Sprintf("legacy-%03d", i)), payload); err != nil {
				return err
			}
		}
		return nil
	}))
	require.NoError(t, cache.SetSageState("legacy-299", []byte(`{"updatedAt":"2030-01-01T00:00:00Z"}`)))
	require.NoError(t, db.Close())

	db, err = bbolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		require.Equal(t, sageStateEntryLimit, tx.Bucket(bucketSageState).Stats().KeyN)
		require.Equal(t, []byte("node"), tx.Bucket(bucketSelected).Get([]byte("group")))
		require.Equal(t, []byte("preserved"), tx.Bucket(bucketStorage).Get([]byte("unrelated")))
		return nil
	}))
}

func TestSageStateWriterLeasesAreBoundedBeforeFirstPayload(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	for i := 0; i < sageStateEntryLimit+44; i++ {
		_, token, err := cache.GetSageStateWithToken(fmt.Sprintf("lease-%03d", i))
		require.NoError(t, err)
		require.Len(t, token, sageStateTokenSize)
	}
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketSageStateMeta)
		require.NotNil(t, meta)
		require.Equal(t, sageStateEntryLimit, meta.Stats().KeyN)
		require.NotNil(t, meta.Get([]byte(fmt.Sprintf("lease-%03d", sageStateEntryLimit+43))), "current lease must be protected from its own retention pass")
		return nil
	}))
}
