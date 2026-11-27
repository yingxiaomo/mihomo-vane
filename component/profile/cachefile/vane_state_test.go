package cachefile

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func TestVaneStateStoreIsDedicatedAndDurable(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	missing, err := cache.GetVaneState("missing", 1)
	require.NoError(t, err)
	require.Nil(t, missing)

	payload := []byte(`{"schemaVersion":1,"group":"vane","updatedAt":"2026-11-14T00:00:00Z"}`)
	require.NoError(t, cache.SetVaneState("vane-state-v1:key", payload))

	actual, err := cache.GetVaneState("vane-state-v1:key", 1)
	require.NoError(t, err)
	require.Equal(t, payload, actual)
}

func TestVaneStateStoreReportsUnavailableAndOversize(t *testing.T) {
	cache := &CacheFile{}
	_, err := cache.GetVaneState("key", 1)
	require.ErrorIs(t, err, ErrCacheUnavailable)
	require.ErrorIs(t, cache.SetVaneState("key", []byte("value")), ErrCacheUnavailable)

	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache.DB = db
	require.Error(t, cache.SetVaneState("key", make([]byte, vaneStatePayloadLimit+1)))
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketVaneState)
		if err != nil {
			return err
		}
		return bucket.Put([]byte("legacy-oversize"), make([]byte, vaneStatePayloadLimit+1))
	}))
	_, token, err := cache.GetVaneStateWithToken("legacy-oversize", 1)
	require.ErrorIs(t, err, ErrVaneStatePayloadTooLarge)
	require.Len(t, token, vaneStateTokenSize)
	replacement := []byte(`{"updatedAt":"2026-11-14T00:00:00Z","revision":1}`)
	_, err = cache.CompareAndSwapVaneState("legacy-oversize", token, replacement)
	require.NoError(t, err)
	actual, err := cache.GetVaneState("legacy-oversize", 1)
	require.NoError(t, err)
	require.Equal(t, replacement, actual)
}

func TestVaneStateOversizedFutureSchemaCannotBeDowngraded(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	payload := append([]byte(`{"schemaVersion":2,"padding":"`), bytes.Repeat([]byte{'x'}, vaneStatePayloadLimit)...)
	payload = append(payload, []byte(`"}`)...)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, createErr := tx.CreateBucketIfNotExists(bucketVaneState)
		if createErr != nil {
			return createErr
		}
		return bucket.Put([]byte("future"), payload)
	}))

	_, token, err := cache.GetVaneStateWithToken("future", 1)
	require.ErrorIs(t, err, ErrVaneStateIncompatibleSchema)
	require.Len(t, token, vaneStateTokenSize)
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		require.Equal(t, payload, []byte(tx.Bucket(bucketVaneState).Get([]byte("future"))))
		return nil
	}))
}

func TestVaneStateFreshLeasesOutliveLegacyRetentionEntries(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		meta, createErr := tx.CreateBucketIfNotExists(bucketVaneStateMeta)
		if createErr != nil {
			return createErr
		}
		for i := 0; i < vaneStateEntryLimit-1; i++ {
			if putErr := meta.Put([]byte(fmt.Sprintf("vane-state-v1:stale-%03d", i)), bytes.Repeat([]byte{byte(i)}, vaneStateTokenSize)); putErr != nil {
				return putErr
			}
		}
		return nil
	}))

	_, tokenA, err := cache.GetVaneStateWithToken("vane-state-v1:--fresh-a", 1)
	require.NoError(t, err)
	_, tokenB, err := cache.GetVaneStateWithToken("vane-state-v1:--fresh-b", 1)
	require.NoError(t, err)
	_, err = cache.CompareAndSwapVaneState("vane-state-v1:--fresh-a", tokenA, []byte(`{"schemaVersion":1,"updatedAt":"2026-11-15T00:00:00Z"}`))
	require.NoError(t, err, "a fresh active lease must be retained ahead of legacy zero-time leases")
	_, err = cache.CompareAndSwapVaneState("vane-state-v1:--fresh-b", tokenB, []byte(`{"schemaVersion":1,"updatedAt":"2026-11-15T00:00:01Z"}`))
	require.NoError(t, err)
}

func TestVaneStateStorePrunesLegacyOversizedBucketOnEverySave(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketVaneState)
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
	require.NoError(t, cache.SetVaneState("legacy-299", payload))

	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketVaneState)
		require.Equal(t, vaneStateEntryLimit, bucket.Stats().KeyN)
		require.Nil(t, bucket.Get([]byte("legacy-000")))
		require.Equal(t, payload, bucket.Get([]byte("legacy-299")))
		return nil
	}))
}

func TestVaneStateCompareAndSwapRejectsStaleAndAbsentRace(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}

	missing, absentToken, err := cache.GetVaneStateWithToken("key", 1)
	require.NoError(t, err)
	require.Nil(t, missing)
	require.Len(t, absentToken, vaneStateTokenSize)

	first := []byte(`{"updatedAt":"2026-11-14T00:00:00Z","revision":1}`)
	firstToken, err := cache.CompareAndSwapVaneState("key", absentToken, first)
	require.NoError(t, err)
	require.Len(t, firstToken, vaneStateTokenSize)

	_, err = cache.CompareAndSwapVaneState("key", nil, []byte(`{"revision":0}`))
	require.ErrorIs(t, err, ErrVaneStateConflict, "an absent-at-load writer must not overwrite a newly created row")

	second := []byte(`{"updatedAt":"2026-11-14T00:00:01Z","revision":2}`)
	secondToken, err := cache.CompareAndSwapVaneState("key", firstToken, second)
	require.NoError(t, err)
	require.NotEqual(t, firstToken, secondToken)

	_, err = cache.CompareAndSwapVaneState("key", firstToken, []byte(`{"revision":1}`))
	require.ErrorIs(t, err, ErrVaneStateConflict, "a delayed old writer must not replace the newer revision")
	actual, actualToken, err := cache.GetVaneStateWithToken("key", 1)
	require.NoError(t, err)
	require.Equal(t, second, actual)
	require.NotEqual(t, secondToken, actualToken, "opening a new writer lease must fence the previous writer")
	_, err = cache.CompareAndSwapVaneState("key", secondToken, []byte(`{"revision":3}`))
	require.ErrorIs(t, err, ErrVaneStateConflict, "opening alone must fence the previous owner before the new owner saves")

	backToFirstToken, err := cache.CompareAndSwapVaneState("key", actualToken, first)
	require.NoError(t, err)
	require.NotEqual(t, firstToken, backToFirstToken, "A-B-A payload cycles must still rotate the writer fence")
	_, err = cache.CompareAndSwapVaneState("key", firstToken, []byte(`{"revision":99}`))
	require.ErrorIs(t, err, ErrVaneStateConflict, "an old A writer must stay fenced after an A-B-A cycle")
}

func TestVaneStateLegacyPruneSurvivesReopenAndPreservesOtherBuckets(t *testing.T) {
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
		vane, err := tx.CreateBucketIfNotExists(bucketVaneState)
		if err != nil {
			return err
		}
		for i := 0; i < 300; i++ {
			payload := []byte(fmt.Sprintf(`{"updatedAt":%q}`, time.Unix(int64(i+1), 0).UTC().Format(time.RFC3339Nano)))
			if err := vane.Put([]byte(fmt.Sprintf("legacy-%03d", i)), payload); err != nil {
				return err
			}
		}
		return nil
	}))
	require.NoError(t, cache.SetVaneState("legacy-299", []byte(`{"updatedAt":"2030-01-01T00:00:00Z"}`)))
	require.NoError(t, db.Close())

	db, err = bbolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		require.Equal(t, vaneStateEntryLimit, tx.Bucket(bucketVaneState).Stats().KeyN)
		require.Equal(t, []byte("node"), tx.Bucket(bucketSelected).Get([]byte("group")))
		require.Equal(t, []byte("preserved"), tx.Bucket(bucketStorage).Get([]byte("unrelated")))
		return nil
	}))
}

func TestVaneStateWriterLeasesAreBoundedBeforeFirstPayload(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	for i := 0; i < vaneStateEntryLimit+44; i++ {
		_, token, err := cache.GetVaneStateWithToken(fmt.Sprintf("lease-%03d", i), 1)
		require.NoError(t, err)
		require.Len(t, token, vaneStateTokenSize)
	}
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketVaneStateMeta)
		require.NotNil(t, meta)
		require.Equal(t, vaneStateEntryLimit, meta.Stats().KeyN)
		require.NotNil(t, meta.Get([]byte(fmt.Sprintf("lease-%03d", vaneStateEntryLimit+43))), "current lease must be protected from its own retention pass")
		return nil
	}))
}

// AUDIT-2026-11-28: the oversized-row schema gate follows the writer's schema
// version, passed in by the caller — not a pinned constant. A row at the
// writer's own schema stays recoverable through the replacement path; only a
// genuinely newer declaration is protected from downgrade.
func TestVaneStateOversizedGateFollowsWriterSchema(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/cache.db", 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	cache := &CacheFile{DB: db}
	payload := append([]byte(`{"schemaVersion":3,"padding":"`), bytes.Repeat([]byte{'x'}, vaneStatePayloadLimit)...)
	payload = append(payload, []byte(`"}`)...)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		bucket, createErr := tx.CreateBucketIfNotExists(bucketVaneState)
		if createErr != nil {
			return createErr
		}
		return bucket.Put([]byte("writer-schema"), payload)
	}))

	_, _, err = cache.GetVaneStateWithToken("writer-schema", 3)
	require.ErrorIs(t, err, ErrVaneStatePayloadTooLarge,
		"a row at the writer's schema stays recoverable for replacement")
	_, _, err = cache.GetVaneStateWithToken("writer-schema", 2)
	require.ErrorIs(t, err, ErrVaneStateIncompatibleSchema,
		"a row above the writer's schema is protected from downgrade")
}
