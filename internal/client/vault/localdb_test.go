package vault_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalDB_SaveAndLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)

	data := vault.VaultData{
		UserID:   "user-1",
		Username: "alice",
		Items: []vault.Item{
			{ID: "item-1", Type: "credential", Metadata: "github", Version: 1, CreatedAt: time.Now()},
		},
		SyncedAt: time.Now(),
	}

	err := db.Save(data, []byte("master-password"), nil)
	require.NoError(t, err)

	loaded, err := db.Load([]byte("master-password"), nil)
	require.NoError(t, err)
	assert.Equal(t, data.UserID, loaded.UserID)
	assert.Equal(t, data.Username, loaded.Username)
	assert.Len(t, loaded.Items, 1)
	assert.Equal(t, "item-1", loaded.Items[0].ID)
}

func TestLocalDB_WrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)

	err := db.Save(vault.VaultData{UserID: "u1"}, []byte("correct"), nil)
	require.NoError(t, err)

	_, err = db.Load([]byte("wrong"), nil)
	assert.ErrorIs(t, err, vault.ErrWrongPassword)
}

func TestLocalDB_WithKeyfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	keyfile := []byte("my-keyfile-content-64-bytes-padding-to-make-it-long-enough-here!")
	db := vault.NewLocalDB(path)

	err := db.Save(vault.VaultData{UserID: "u1"}, []byte("pass"), keyfile)
	require.NoError(t, err)

	// Correct password + keyfile
	_, err = db.Load([]byte("pass"), keyfile)
	require.NoError(t, err)

	// Correct password, wrong keyfile
	_, err = db.Load([]byte("pass"), []byte("wrong-keyfile"))
	assert.ErrorIs(t, err, vault.ErrWrongPassword)

	// Correct password, no keyfile
	_, err = db.Load([]byte("pass"), nil)
	assert.ErrorIs(t, err, vault.ErrWrongPassword)
}

func TestLocalDB_NoKeyfile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)

	data := vault.VaultData{UserID: "u1", Username: "bob"}
	require.NoError(t, db.Save(data, []byte("pass"), nil))

	loaded, err := db.Load([]byte("pass"), nil)
	require.NoError(t, err)
	assert.Equal(t, data.UserID, loaded.UserID)
	assert.Equal(t, data.Username, loaded.Username)
}

func TestLocalDB_Keyfile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	keyfile := []byte("my-keyfile-content-64-bytes-padding-to-make-it-long-enough-here!")
	db := vault.NewLocalDB(path)

	data := vault.VaultData{UserID: "u2", Username: "carol"}
	require.NoError(t, db.Save(data, []byte("pass"), keyfile))

	loaded, err := db.Load([]byte("pass"), keyfile)
	require.NoError(t, err)
	assert.Equal(t, data.UserID, loaded.UserID)
	assert.Equal(t, data.Username, loaded.Username)
}

func TestLocalDB_CorruptedMagicHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)

	require.NoError(t, db.Save(vault.VaultData{UserID: "u1"}, []byte("pass"), nil))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	copy(raw[:4], []byte("XXXX")) // corrupt magic
	require.NoError(t, os.WriteFile(path, raw, 0600))

	_, err = db.Load([]byte("pass"), nil)
	assert.ErrorIs(t, err, vault.ErrInvalidVault)
}

func TestLocalDB_UnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)

	require.NoError(t, db.Save(vault.VaultData{UserID: "u1"}, []byte("pass"), nil))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	// version field is bytes [4:6], big-endian uint16.
	binary.BigEndian.PutUint16(raw[4:6], 99)
	require.NoError(t, os.WriteFile(path, raw, 0600))

	// The current Load() does not reject unknown versions explicitly; it keeps
	// parsing the rest of the (unmodified) body, so this documents that a
	// version bump alone still round-trips rather than silently failing.
	loaded, err := db.Load([]byte("pass"), nil)
	require.NoError(t, err)
	assert.Equal(t, "u1", loaded.UserID)
}

func TestLocalDB_TruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)

	require.NoError(t, db.Save(vault.VaultData{UserID: "u1"}, []byte("pass"), nil))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw[:10], 0600)) // truncate mid-header

	_, err = db.Load([]byte("pass"), nil)
	assert.ErrorIs(t, err, vault.ErrInvalidVault)
}

func TestLocalDB_NotFound(t *testing.T) {
	db := vault.NewLocalDB("/tmp/nonexistent-gkdb-file.gkdb")
	_, err := db.Load([]byte("pass"), nil)
	assert.ErrorIs(t, err, vault.ErrVaultNotFound)
}

func TestLocalDB_Exists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.gkdb")
	db := vault.NewLocalDB(path)
	assert.False(t, db.Exists())

	err := db.Save(vault.VaultData{}, []byte("pass"), nil)
	require.NoError(t, err)
	assert.True(t, db.Exists())

	require.NoError(t, os.Remove(path))
	assert.False(t, db.Exists())
}
