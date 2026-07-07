package vault_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

// cacheEnvelope mirrors the unexported on-disk format in localcache.go so
// tests can build a cache file with a deliberately malformed entry.
type cacheEnvelope struct {
	Version   int    `json:"v"`
	UpdatedAt int64  `json:"ts"`
	Data      []byte `json:"d"`
}

func TestCacheKey_Deterministic(t *testing.T) {
	k1 := vault.CacheKey("refresh-token-abc")
	k2 := vault.CacheKey("refresh-token-abc")
	assert.Equal(t, k1, k2)
	assert.Len(t, k1, 32)
}

func TestCacheKey_DifferentTokens(t *testing.T) {
	k1 := vault.CacheKey("token-a")
	k2 := vault.CacheKey("token-b")
	assert.NotEqual(t, k1, k2)
}

func TestCache_SaveAndLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	key := vault.CacheKey("refresh-token")

	items := []*commonpb.VaultItem{
		commonpb.VaultItem_builder{Id: "item-1", UserId: "user-1", Type: commonpb.ItemType_CREDENTIAL, Metadata: "github", Version: 1}.Build(),
		commonpb.VaultItem_builder{Id: "item-2", UserId: "user-1", Type: commonpb.ItemType_TEXT, Metadata: "note", Version: 2}.Build(),
	}

	require.NoError(t, vault.Save(path, key, items))

	loaded, updatedAt, err := vault.Load(path, key)
	require.NoError(t, err)
	assert.False(t, updatedAt.IsZero())
	require.Len(t, loaded, 2)
	assert.Equal(t, "item-1", loaded[0].GetId())
	assert.Equal(t, "github", loaded[0].GetMetadata())
	assert.Equal(t, "item-2", loaded[1].GetId())
}

func TestCache_SaveAndLoad_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	key := vault.CacheKey("refresh-token")

	require.NoError(t, vault.Save(path, key, nil))

	loaded, _, err := vault.Load(path, key)
	require.NoError(t, err)
	assert.Empty(t, loaded)
}

func TestCache_Load_NotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.bin")
	key := vault.CacheKey("refresh-token")

	_, _, err := vault.Load(path, key)
	assert.ErrorIs(t, err, vault.ErrCacheNotFound)
}

func TestCache_Load_WrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	key := vault.CacheKey("refresh-token")
	wrongKey := vault.CacheKey("other-token")

	items := []*commonpb.VaultItem{commonpb.VaultItem_builder{Id: "item-1", UserId: "user-1"}.Build()}
	require.NoError(t, vault.Save(path, key, items))

	_, _, err := vault.Load(path, wrongKey)
	assert.Error(t, err)
}

func TestCache_Load_CorruptedEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	key := vault.CacheKey("refresh-token")

	require.NoError(t, os.WriteFile(path, []byte("not valid json"), 0600))

	_, _, err := vault.Load(path, key)
	assert.Error(t, err)
}

func TestCache_Load_SkipsCorruptedItems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	key := vault.CacheKey("refresh-token")

	// Build a cache envelope by hand: one well-formed protojson item and one
	// entry that cannot be parsed as a VaultItem. Load() must skip the bad
	// entry and still return the good one instead of failing outright.
	raw := []json.RawMessage{
		json.RawMessage(`{"id":"item-1","userId":"user-1"}`),
		json.RawMessage(`{"id": 12345}`), // "id" must be a string; protojson rejects the type mismatch
	}
	plaintext, err := json.Marshal(raw)
	require.NoError(t, err)

	ciphertext, err := crypto.Encrypt(key, plaintext)
	require.NoError(t, err)

	env := cacheEnvelope{Version: 1, UpdatedAt: time.Now().Unix(), Data: ciphertext}
	payload, err := json.Marshal(env)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, payload, 0600))

	loaded, _, err := vault.Load(path, key)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "item-1", loaded[0].GetId())
}
