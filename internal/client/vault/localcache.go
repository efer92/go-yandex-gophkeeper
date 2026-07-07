// Package vault manages the local encrypted vault cache for offline access.
package vault

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

// cacheEnvelope is the on-disk format for the encrypted vault cache.
type cacheEnvelope struct {
	Version   int    `json:"v"`
	UpdatedAt int64  `json:"ts"`
	Data      []byte `json:"d"` // ChaCha20-Poly1305 encrypted protojson array
}

// CacheKey derives a 32-byte encryption key from the refresh token using HKDF-SHA256.
// The refresh token is long-lived and stored in config, making it a stable key source.
func CacheKey(refreshToken string) []byte {
	r := hkdf.New(sha256.New, []byte(refreshToken), nil, []byte("gophkeeper-local-vault-cache-v1"))
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

// Save encrypts and writes items to path with 0600 permissions.
func Save(path string, key []byte, items []*commonpb.VaultItem) error {
	// Serialize each item with protojson then wrap in a JSON array.
	marshaler := protojson.MarshalOptions{EmitUnpopulated: false}
	raw := make([]json.RawMessage, len(items))
	for i, it := range items {
		b, err := marshaler.Marshal(it)
		if err != nil {
			return fmt.Errorf("marshal item %d: %w", i, err)
		}
		raw[i] = json.RawMessage(b)
	}
	plaintext, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt cache: %w", err)
	}

	env := cacheEnvelope{
		Version:   1,
		UpdatedAt: time.Now().Unix(),
		Data:      ciphertext,
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	if err := os.WriteFile(path, payload, 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	return nil
}

// Load reads, decrypts, and returns vault items from the local cache.
// Returns ErrCacheNotFound if the file does not exist or is unreadable.
func Load(path string, key []byte) ([]*commonpb.VaultItem, time.Time, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, ErrCacheNotFound
	}

	var env cacheEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse cache: %w", err)
	}

	plaintext, err := crypto.Decrypt(key, env.Data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decrypt cache: %w", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(plaintext, &raw); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse items: %w", err)
	}

	items := make([]*commonpb.VaultItem, 0, len(raw))
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	for _, r := range raw {
		it := &commonpb.VaultItem{}
		if err := unmarshaler.Unmarshal(r, proto.Message(it)); err != nil {
			continue // skip corrupted entries
		}
		items = append(items, it)
	}

	return items, time.Unix(env.UpdatedAt, 0), nil
}

// ErrCacheNotFound is returned when no local cache file exists.
var ErrCacheNotFound = fmt.Errorf("local cache not found")
