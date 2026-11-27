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
	ErrCacheUnavailable            = errors.New("cache database unavailable")
	ErrVaneStateConflict           = errors.New("vane state changed since load")
	ErrVaneStatePayloadTooLarge    = errors.New("vane state payload too large")
	ErrVaneStateIncompatibleSchema = errors.New("vane state uses a newer schema")
)

const (
	vaneStatePayloadLimit = 2 * 1024 * 1024
	vaneStateEntryLimit   = 256
	vaneStateTokenSize    = 16
)

// supportedSchema is the schema version THIS binary writes, passed in from the
// caller (cachefile cannot import the learning layer). Rows declaring a newer
// schema are protected from downgrade; rows at or below it stay recoverable
// through the payload-too-large replacement path.
func vaneOversizedStateError(value []byte, supportedSchema int) error {
	var header struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(value, &header); err != nil {
		// Malformed legacy rows remain recoverable; only a valid declaration of a
		// newer schema is protected from downgrade.
		return fmt.Errorf("%w: exceeds %d bytes", ErrVaneStatePayloadTooLarge, vaneStatePayloadLimit)
	}
	if header.SchemaVersion > supportedSchema {
		return fmt.Errorf("%w: schema %d", ErrVaneStateIncompatibleSchema, header.SchemaVersion)
	}
	return fmt.Errorf("%w: exceeds %d bytes", ErrVaneStatePayloadTooLarge, vaneStatePayloadLimit)
}

type vaneStateEntry struct {
	key       []byte
	updatedAt time.Time
}

type vaneStateTimestamp struct {
	UpdatedAt time.Time `json:"updatedAt"`
}

type vaneStateLeaseMeta struct {
	Token     []byte    `json:"token"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func encodeVaneStateLease(token []byte, updatedAt time.Time) ([]byte, error) {
	return json.Marshal(vaneStateLeaseMeta{Token: token, UpdatedAt: updatedAt.UTC()})
}

func decodeVaneStateLease(value []byte) (token []byte, updatedAt time.Time, ok bool) {
	if len(value) == vaneStateTokenSize {
		return append([]byte(nil), value...), time.Time{}, true
	}
	var meta vaneStateLeaseMeta
	if err := json.Unmarshal(value, &meta); err != nil || len(meta.Token) != vaneStateTokenSize {
		return nil, time.Time{}, false
	}
	return append([]byte(nil), meta.Token...), meta.UpdatedAt, true
}

func newVaneStateToken() ([]byte, error) {
	token := make([]byte, vaneStateTokenSize)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate vane state token: %w", err)
	}
	return token, nil
}

func (c *CacheFile) GetVaneState(key string, supportedSchema int) ([]byte, error) {
	if c == nil || c.DB == nil {
		return nil, ErrCacheUnavailable
	}
	var data []byte
	err := c.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketVaneState)
		if bucket == nil {
			return nil
		}
		if value := bucket.Get([]byte(key)); value != nil {
			if len(value) > vaneStatePayloadLimit {
				return vaneOversizedStateError(value, supportedSchema)
			}
			data = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read vane state: %w", err)
	}
	return data, nil
}

// GetVaneStateWithToken opens a fenced writer lease for key. The opaque
// random token is durable even while the payload is absent, so delete/recreate
// and A->B->A content cycles cannot make an old writer current again.
func (c *CacheFile) GetVaneStateWithToken(key string, supportedSchema int) ([]byte, []byte, error) {
	if c == nil || c.DB == nil {
		return nil, nil, ErrCacheUnavailable
	}
	candidateToken, err := newVaneStateToken()
	if err != nil {
		return nil, nil, err
	}
	var data, token []byte
	var oversizedErr error
	err = c.DB.Update(func(tx *bbolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketVaneStateMeta)
		if err != nil {
			return err
		}
		keyBytes := []byte(key)
		token = append([]byte(nil), candidateToken...)
		lease, err := encodeVaneStateLease(token, time.Now())
		if err != nil {
			return err
		}
		if err := meta.Put(keyBytes, lease); err != nil {
			return err
		}
		bucket := tx.Bucket(bucketVaneState)
		if err := pruneVaneStateBuckets(bucket, meta, keyBytes); err != nil {
			return err
		}
		if bucket == nil {
			return nil
		}
		if value := bucket.Get(keyBytes); value != nil {
			if len(value) > vaneStatePayloadLimit {
				oversizedErr = vaneOversizedStateError(value, supportedSchema)
				return nil
			}
			data = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read vane state: %w", err)
	}
	if oversizedErr != nil {
		return nil, token, oversizedErr
	}
	return data, token, nil
}

func (c *CacheFile) SetVaneState(key string, data []byte) error {
	_, err := c.setVaneState(key, nil, false, data)
	return err
}

// CompareAndSwapVaneState commits data only when the row still has the
// token returned by GetVaneStateWithToken. This protects fresh state from
// a delayed writer, including absent-at-load races.
func (c *CacheFile) CompareAndSwapVaneState(key string, expectedToken, data []byte) ([]byte, error) {
	return c.setVaneState(key, expectedToken, true, data)
}

func (c *CacheFile) setVaneState(key string, expectedToken []byte, compare bool, data []byte) ([]byte, error) {
	if c == nil || c.DB == nil {
		return nil, ErrCacheUnavailable
	}
	if len(data) > vaneStatePayloadLimit {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrVaneStatePayloadTooLarge, vaneStatePayloadLimit)
	}
	nextToken, err := newVaneStateToken()
	if err != nil {
		return nil, err
	}
	err = c.DB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketVaneState)
		if err != nil {
			return err
		}
		meta, err := tx.CreateBucketIfNotExists(bucketVaneStateMeta)
		if err != nil {
			return err
		}
		keyBytes := []byte(key)
		if compare {
			currentToken, _, ok := decodeVaneStateLease(meta.Get(keyBytes))
			if !ok || !bytes.Equal(currentToken, expectedToken) {
				return ErrVaneStateConflict
			}
		}
		if err := bucket.Put(keyBytes, data); err != nil {
			return err
		}
		lease, err := encodeVaneStateLease(nextToken, time.Now())
		if err != nil {
			return err
		}
		if err := meta.Put(keyBytes, lease); err != nil {
			return err
		}
		return pruneVaneStateBuckets(bucket, meta, keyBytes)
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), nextToken...), nil
}

func pruneVaneStateBuckets(data, meta *bbolt.Bucket, protectedKey []byte) error {
	entriesByKey := make(map[string]vaneStateEntry)
	if data != nil {
		cursor := data.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			stamp := vaneStateTimestamp{}
			_ = json.Unmarshal(value, &stamp)
			copied := append([]byte(nil), key...)
			entriesByKey[string(copied)] = vaneStateEntry{key: copied, updatedAt: stamp.UpdatedAt}
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
			if _, leaseUpdatedAt, ok := decodeVaneStateLease(value); ok && leaseUpdatedAt.After(entry.updatedAt) {
				entry.updatedAt = leaseUpdatedAt
			}
			entriesByKey[string(copied)] = entry
		}
	}
	if len(entriesByKey) <= vaneStateEntryLimit {
		return nil
	}
	entries := make([]vaneStateEntry, 0, len(entriesByKey))
	for _, entry := range entriesByKey {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].updatedAt.Equal(entries[j].updatedAt) {
			return string(entries[i].key) < string(entries[j].key)
		}
		return entries[i].updatedAt.Before(entries[j].updatedAt)
	})
	remove := len(entries) - vaneStateEntryLimit
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
