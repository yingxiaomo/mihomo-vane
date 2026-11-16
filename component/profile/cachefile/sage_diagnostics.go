package cachefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/metacubex/bbolt"
)

const (
	sageDiagnosticsPayloadLimit = 256 * 1024
	sageDiagnosticsEntryLimit   = 256
)

type sageDiagnosticsEntry struct {
	key       []byte
	updatedAt time.Time
}

type sageDiagnosticsTimestamp struct {
	UpdatedAt time.Time `json:"updatedAt"`
}

var ErrCacheUnavailable = errors.New("cache database unavailable")

func (c *CacheFile) GetSageDiagnostics(key string) ([]byte, error) {
	if c == nil || c.DB == nil {
		return nil, ErrCacheUnavailable
	}
	var data []byte
	err := c.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSageDiagnostics)
		if bucket == nil {
			return nil
		}
		if value := bucket.Get([]byte(key)); value != nil {
			data = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read sage diagnostics: %w", err)
	}
	return data, nil
}

func (c *CacheFile) SetSageDiagnostics(key string, data []byte) error {
	if c == nil || c.DB == nil {
		return ErrCacheUnavailable
	}
	if len(data) > sageDiagnosticsPayloadLimit {
		return fmt.Errorf("sage diagnostics payload exceeds %d bytes", sageDiagnosticsPayloadLimit)
	}
	return c.DB.Batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSageDiagnostics)
		if err != nil {
			return err
		}
		isNew := bucket.Get([]byte(key)) == nil
		entryCount := bucket.Stats().KeyN
		if err := bucket.Put([]byte(key), data); err != nil {
			return err
		}
		postWriteCount := entryCount
		if isNew {
			postWriteCount++
		}
		if postWriteCount <= sageDiagnosticsEntryLimit {
			return nil
		}
		entries := make([]sageDiagnosticsEntry, 0, postWriteCount)
		cursor := bucket.Cursor()
		for entryKey, value := cursor.First(); entryKey != nil; entryKey, value = cursor.Next() {
			stamp := sageDiagnosticsTimestamp{}
			_ = json.Unmarshal(value, &stamp)
			entries = append(entries, sageDiagnosticsEntry{key: append([]byte(nil), entryKey...), updatedAt: stamp.UpdatedAt})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].updatedAt.Equal(entries[j].updatedAt) {
				return string(entries[i].key) < string(entries[j].key)
			}
			return entries[i].updatedAt.Before(entries[j].updatedAt)
		})
		for i := 0; i < len(entries)-sageDiagnosticsEntryLimit; i++ {
			if err := bucket.Delete(entries[i].key); err != nil {
				return err
			}
		}
		return nil
	})
}
