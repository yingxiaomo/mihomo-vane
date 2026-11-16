package cachefile

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/metacubex/bbolt"
)

var (
	ErrSageStateConflict           = errors.New("sage state changed since load")
	ErrSageStatePayloadTooLarge    = errors.New("sage state payload too large")
	ErrSageStateIncompatibleSchema = errors.New("sage state uses a newer schema")
)

const (
	sageStatePayloadLimit           = 2 * 1024 * 1024
	sageStateEntryLimit             = 256
	sageStateTokenSize              = 16
	sageStateSupportedSchemaVersion = 1
)

func sageOversizedStateError(value []byte) error {
	var header struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(value, &header); err != nil {
		// Malformed legacy rows remain recoverable; only a valid declaration of a
		// newer schema is protected from downgrade.
		return fmt.Errorf("%w: exceeds %d bytes", ErrSageStatePayloadTooLarge, sageStatePayloadLimit)
	}
	if header.SchemaVersion > sageStateSupportedSchemaVersion {
		return fmt.Errorf("%w: schema %d", ErrSageStateIncompatibleSchema, header.SchemaVersion)
	}
	return fmt.Errorf("%w: exceeds %d bytes", ErrSageStatePayloadTooLarge, sageStatePayloadLimit)
}

type sageStateEntry struct {
	key       []byte
	updatedAt time.Time
}

type sageStateTimestamp struct {
	UpdatedAt time.Time `json:"updatedAt"`
}

type sageStateLeaseMeta struct {
	Token     []byte    `json:"token"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func encodeSageStateLease(token []byte, updatedAt time.Time) ([]byte, error) {
	return json.Marshal(sageStateLeaseMeta{Token: token, UpdatedAt: updatedAt.UTC()})
}

func decodeSageStateLease(value []byte) (token []byte, updatedAt time.Time, ok bool) {
	if len(value) == sageStateTokenSize {
		return append([]byte(nil), value...), time.Time{}, true
	}
	var meta sageStateLeaseMeta
	if err := json.Unmarshal(value, &meta); err != nil || len(meta.Token) != sageStateTokenSize {
		return nil, time.Time{}, false
	}
	return append([]byte(nil), meta.Token...), meta.UpdatedAt, true
}

func newSageStateToken() ([]byte, error) {
	token := make([]byte, sageStateTokenSize)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate sage state token: %w", err)
	}
	return token, nil
}

func (c *CacheFile) GetSageState(key string) ([]byte, error) {
	if c == nil || c.DB == nil {
		return nil, ErrCacheUnavailable
	}
	var data []byte
	err := c.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSageState)
		if bucket == nil {
			return nil
		}
		if value := bucket.Get([]byte(key)); value != nil {
			if len(value) > sageStatePayloadLimit {
				return sageOversizedStateError(value)
			}
			data = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read sage state: %w", err)
	}
	return data, nil
}

// GetSageStateWithToken opens a fenced writer lease for key. The opaque
// random token is durable even while the payload is absent, so delete/recreate
// and A->B->A content cycles cannot make an old writer current again.
func (c *CacheFile) GetSageStateWithToken(key string) ([]byte, []byte, error) {
	if c == nil || c.DB == nil {
		return nil, nil, ErrCacheUnavailable
	}
	candidateToken, err := newSageStateToken()
	if err != nil {
		return nil, nil, err
	}
	var data, token []byte
	var oversizedErr error
	err = c.DB.Update(func(tx *bbolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketSageStateMeta)
		if err != nil {
			return err
		}
		keyBytes := []byte(key)
		token = append([]byte(nil), candidateToken...)
		lease, err := encodeSageStateLease(token, time.Now())
		if err != nil {
			return err
		}
		if err := meta.Put(keyBytes, lease); err != nil {
			return err
		}
		bucket := tx.Bucket(bucketSageState)
		if err := pruneSageStateBuckets(bucket, meta, keyBytes); err != nil {
			return err
		}
		if bucket == nil {
			return nil
		}
		if value := bucket.Get(keyBytes); value != nil {
			if len(value) > sageStatePayloadLimit {
				oversizedErr = sageOversizedStateError(value)
				return nil
			}
			data = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read sage state: %w", err)
	}
	if oversizedErr != nil {
		return nil, token, oversizedErr
	}
	return data, token, nil
}

func (c *CacheFile) SetSageState(key string, data []byte) error {
	_, err := c.setSageState(key, nil, false, data)
	return err
}

// CompareAndSwapSageState commits data only when the row still has the
// token returned by GetSageStateWithToken. This protects fresh state from
// a delayed writer, including absent-at-load races.
func (c *CacheFile) CompareAndSwapSageState(key string, expectedToken, data []byte) ([]byte, error) {
	return c.setSageState(key, expectedToken, true, data)
}

func (c *CacheFile) setSageState(key string, expectedToken []byte, compare bool, data []byte) ([]byte, error) {
	if c == nil || c.DB == nil {
		return nil, ErrCacheUnavailable
	}
	if len(data) > sageStatePayloadLimit {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrSageStatePayloadTooLarge, sageStatePayloadLimit)
	}
	nextToken, err := newSageStateToken()
	if err != nil {
		return nil, err
	}
	err = c.DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSageState)
		if err != nil {
			return err
		}
		meta, err := tx.CreateBucketIfNotExists(bucketSageStateMeta)
		if err != nil {
			return err
		}
		keyBytes := []byte(key)
		if compare {
			currentToken, _, ok := decodeSageStateLease(meta.Get(keyBytes))
			if !ok || !bytes.Equal(currentToken, expectedToken) {
				return ErrSageStateConflict
			}
		}
		if err := bucket.Put(keyBytes, data); err != nil {
			return err
		}
		lease, err := encodeSageStateLease(nextToken, time.Now())
		if err != nil {
			return err
		}
		if err := meta.Put(keyBytes, lease); err != nil {
			return err
		}
		return pruneSageStateBuckets(bucket, meta, keyBytes)
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), nextToken...), nil
}

func pruneSageStateBuckets(data, meta *bbolt.Bucket, protectedKey []byte) error {
	entriesByKey := make(map[string]sageStateEntry)
	if data != nil {
		cursor := data.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			stamp := sageStateTimestamp{}
			_ = json.Unmarshal(value, &stamp)
			copied := append([]byte(nil), key...)
			entriesByKey[string(copied)] = sageStateEntry{key: copied, updatedAt: stamp.UpdatedAt}
		}
	}
	if meta != nil {
		cursor := meta.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			copied := append([]byte(nil), key...)
			entry := entriesByKey[string(key)]
			if entry.key == nil {
				entry.key = copied
			}
			if _, leaseUpdatedAt, ok := decodeSageStateLease(value); ok && leaseUpdatedAt.After(entry.updatedAt) {
				entry.updatedAt = leaseUpdatedAt
			}
			entriesByKey[string(copied)] = entry
		}
	}
	if len(entriesByKey) <= sageStateEntryLimit {
		return nil
	}
	entries := make([]sageStateEntry, 0, len(entriesByKey))
	for _, entry := range entriesByKey {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].updatedAt.Equal(entries[j].updatedAt) {
			return string(entries[i].key) < string(entries[j].key)
		}
		return entries[i].updatedAt.Before(entries[j].updatedAt)
	})
	remove := len(entries) - sageStateEntryLimit
	for _, entry := range entries {
		if remove == 0 {
			break
		}
		if bytes.Equal(entry.key, protectedKey) {
			continue
		}
		if data != nil {
			if err := data.Delete(entry.key); err != nil {
				return err
			}
		}
		if meta != nil {
			if err := meta.Delete(entry.key); err != nil {
				return err
			}
		}
		remove--
	}
	return nil
}
