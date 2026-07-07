package config_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
)

func TestLoad_ReturnsDefaults(t *testing.T) {
	// Override home to a temp dir so tests don't touch the real ~/.gophkeeper
	t.Setenv("HOME", t.TempDir())

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "localhost:50051", cfg.ServerAddr)
	assert.NotEmpty(t, cfg.VaultPath, "vault path should have a default")
}

func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	original := &config.Config{
		ServerAddr:   "remote.example.com:50051",
		AccessToken:  "access-abc",
		RefreshToken: "refresh-xyz",
		Username:     "alice",
		VaultPath:    filepath.Join(dir, "vault.gkdb"),
	}
	err := config.Save(original)
	require.NoError(t, err)

	loaded, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, original.ServerAddr, loaded.ServerAddr)
	assert.Equal(t, original.AccessToken, loaded.AccessToken)
	assert.Equal(t, original.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, original.Username, loaded.Username)
}
