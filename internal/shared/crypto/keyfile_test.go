package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyfile_WritesBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.kf")

	data, err := crypto.GenerateKeyfile(path)
	require.NoError(t, err)
	assert.Len(t, data, 64)

	on_disk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, data, on_disk)
}

func TestGenerateKeyfile_IsRandom(t *testing.T) {
	dir := t.TempDir()
	d1, _ := crypto.GenerateKeyfile(filepath.Join(dir, "a.kf"))
	d2, _ := crypto.GenerateKeyfile(filepath.Join(dir, "b.kf"))
	assert.NotEqual(t, d1, d2, "two keyfiles must differ")
}

func TestGenerateKeyfile_BadPath(t *testing.T) {
	_, err := crypto.GenerateKeyfile("/nonexistent/dir/key.kf")
	assert.Error(t, err)
}

func TestLoadKeyfile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "load.kf")
	written, _ := crypto.GenerateKeyfile(path)

	loaded, err := crypto.LoadKeyfile(path)
	require.NoError(t, err)
	assert.Equal(t, written, loaded)
}

func TestLoadKeyfile_Missing(t *testing.T) {
	_, err := crypto.LoadKeyfile("/nonexistent/path/key.kf")
	assert.Error(t, err)
}
