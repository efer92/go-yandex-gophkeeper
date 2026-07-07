package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/config"
)

const (
	testJWTSecret   = "this-is-a-sufficiently-long-secret!!"
	testDatabaseURL = "postgres://localhost/gophkeeper"
	testTLSCertFile = "/tmp/server.crt"
	testTLSKeyFile  = "/tmp/server.key"
)

func TestLoad_MissingJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "")
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("TLS_CERT_FILE", testTLSCertFile)
	t.Setenv("TLS_KEY_FILE", testTLSKeyFile)
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_SECRET")
}

func TestLoad_ShortJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "tooshort")
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("TLS_CERT_FILE", testTLSCertFile)
	t.Setenv("TLS_KEY_FILE", testTLSKeyFile)
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32")
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("TLS_CERT_FILE", testTLSCertFile)
	t.Setenv("TLS_KEY_FILE", testTLSKeyFile)
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DATABASE_URL")
}

func TestLoad_MissingTLSCertFile(t *testing.T) {
	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", testTLSKeyFile)
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS_CERT_FILE")
}

func TestLoad_MissingTLSKeyFile(t *testing.T) {
	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("TLS_CERT_FILE", testTLSCertFile)
	t.Setenv("TLS_KEY_FILE", "")
	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS_KEY_FILE")
}

func TestLoad_Success(t *testing.T) {
	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("TLS_CERT_FILE", testTLSCertFile)
	t.Setenv("TLS_KEY_FILE", testTLSKeyFile)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, ":50051", cfg.ServerAddr)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.NotNil(t, cfg.JWTSecret)
	assert.Equal(t, testTLSCertFile, cfg.TLSCertFile)
	assert.Equal(t, testTLSKeyFile, cfg.TLSKeyFile)
}

func TestLoad_CustomServerAddr(t *testing.T) {
	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("TLS_CERT_FILE", testTLSCertFile)
	t.Setenv("TLS_KEY_FILE", testTLSKeyFile)
	t.Setenv("SERVER_ADDR", ":9090")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, ":9090", cfg.ServerAddr)
}
