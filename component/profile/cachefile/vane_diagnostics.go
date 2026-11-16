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
	vaneDiagnosticsPayloadLimit = 256 * 1024
	vaneDiagnosticsEntryLimit   = 256
)

type vaneDiagnosticsEntry struct {
	key       []byte
	updatedAt time.Time
}

type vaneDiagnosticsTimestamp struct {
	UpdatedAt time.Time `json:"updatedAt"`
}

var ErrCacheUnavailable = errors.New("cache database unavailable")

func (c *CacheFile) GetVaneDiagnostics(key string) ([]byte, error) {
	if c == nil || c.DB == nil {
		return nil, ErrCacheUnavailable
	}
	var data []byte
	err := c.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketVaneDiagnostics)
		if bucket == nil {
			return nil
		}
		if value := bucket.Get([]byte(key)); value != nil {
			data = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read vane diagnostics: %w", err)
	}
	return data, nil
}

func (c *CacheFile) SetVaneDiagnostics(key string, data []byte) error {
	if c == nil || c.DB == nil {
		return ErrCacheUnavailable
	}
	if len(data) > vaneDiagnosticsPayloadLimit {
		return fmt.Errorf("vane diagnostics payload exceeds %d bytes", vaneDiagnosticsPayloadLimit)
	}
	return c.DB.Batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketVaneDiagnostics)
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
		if postWriteCount <= vaneDiagnosticsEntryLimit {
			return nil
		}
		entries := make([]vaneDiagnosticsEntry, 0, postWriteCount)
		cursor := bucket.Cursor()
		for entryKey, value := cursor.First(); entryKey != nil; entryKey, value = cursor.Next() {
			stamp := vaneDiagnosticsTimestamp{}
			_ = json.Unmarshal(value, &stamp)
			entries = append(entries, vaneDiagnosticsEntry{key: append([]byte(nil), entryKey...), updatedAt: stamp.UpdatedAt})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].updatedAt.Equal(entries[j].updatedAt) {
				return string(entries[i].key) < string(entries[j].key)
			}
			return entries[i].updatedAt.Before(entries[j].updatedAt)
		})
		for i := 0; i < len(entries)-vaneDiagnosticsEntryLimit; i++ {
			if err := bucket.Delete(entries[i].key); err != nil {
				return err
			}
		}
		return nil
	})
}
