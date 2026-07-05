package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/config"
)

func TestLoad_MissingJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_SECRET")
}

func TestLoad_ShortJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "tooshort")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32")
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-sufficiently-long-secret!!")
	t.Setenv("DATABASE_URL", "")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DATABASE_URL")
}

func TestLoad_Success(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-sufficiently-long-secret!!")
	t.Setenv("DATABASE_URL", "postgres://localhost/gophkeeper")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, ":50051", cfg.ServerAddr)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.NotNil(t, cfg.JWTSecret)
}

func TestLoad_CustomServerAddr(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-sufficiently-long-secret!!")
	t.Setenv("DATABASE_URL", "postgres://localhost/gophkeeper")
	t.Setenv("SERVER_ADDR", ":9090")
	defer t.Setenv("SERVER_ADDR", "")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, ":9090", cfg.ServerAddr)
}
