package jwt_test

import (
	"testing"
	"time"

	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newManager() *jwtpkg.Manager {
	cfg := jwtpkg.Config{
		Secret:          []byte("test-secret-32-bytes-long-enough!"),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	return jwtpkg.NewManager(cfg)
}

func TestIssueAndParseAccessToken(t *testing.T) {
	m := newManager()
	tok, err := m.IssueAccessToken("user-123", true)
	require.NoError(t, err)
	require.NotEmpty(t, tok)

	claims, err := m.ParseAccessToken(tok)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.Subject)
	assert.True(t, claims.MFAVerified)
}

func TestIssueAccessToken_NoMFA(t *testing.T) {
	m := newManager()
	tok, err := m.IssueAccessToken("user-456", false)
	require.NoError(t, err)

	claims, err := m.ParseAccessToken(tok)
	require.NoError(t, err)
	assert.False(t, claims.MFAVerified)
}

func TestParseAccessToken_Expired(t *testing.T) {
	cfg := jwtpkg.Config{
		Secret:         []byte("test-secret-32-bytes-long-enough!"),
		AccessTokenTTL: -time.Second,
	}
	m := jwtpkg.NewManager(cfg)
	tok, err := m.IssueAccessToken("user-123", false)
	require.NoError(t, err)

	_, err = m.ParseAccessToken(tok)
	assert.ErrorIs(t, err, jwtpkg.ErrTokenExpired)
}

func TestParseAccessToken_InvalidSignature(t *testing.T) {
	m := newManager()
	tok, err := m.IssueAccessToken("user-123", false)
	require.NoError(t, err)

	m2 := jwtpkg.NewManager(jwtpkg.Config{Secret: []byte("wrong-secret-padded-to-32-bytes!!")})
	_, err = m2.ParseAccessToken(tok)
	assert.ErrorIs(t, err, jwtpkg.ErrTokenInvalid)
}

func TestParseAccessToken_Malformed(t *testing.T) {
	m := newManager()
	_, err := m.ParseAccessToken("not.a.jwt")
	assert.ErrorIs(t, err, jwtpkg.ErrTokenInvalid)
}

func TestIssueAndParseRefreshToken(t *testing.T) {
	m := newManager()
	tok, err := m.IssueRefreshToken("user-123")
	require.NoError(t, err)

	sub, err := m.ParseRefreshToken(tok)
	require.NoError(t, err)
	assert.Equal(t, "user-123", sub)
}

func TestDefaultConfig(t *testing.T) {
	cfg := jwtpkg.DefaultConfig([]byte("secret"))
	assert.Equal(t, []byte("secret"), cfg.Secret)
	assert.Equal(t, 15*time.Minute, cfg.AccessTokenTTL)
	assert.Equal(t, 30*24*time.Hour, cfg.RefreshTokenTTL)
}

func TestParseRefreshToken_Malformed(t *testing.T) {
	m := newManager()
	_, err := m.ParseRefreshToken("garbage")
	assert.ErrorIs(t, err, jwtpkg.ErrTokenInvalid)
}

func TestParseRefreshToken_Expired(t *testing.T) {
	cfg := jwtpkg.Config{
		Secret:          []byte("test-secret-32-bytes-long-enough!"),
		RefreshTokenTTL: -time.Second,
	}
	m := jwtpkg.NewManager(cfg)
	tok, err := m.IssueRefreshToken("user-123")
	require.NoError(t, err)

	_, err = m.ParseRefreshToken(tok)
	assert.ErrorIs(t, err, jwtpkg.ErrTokenExpired)
}

func TestParseRefreshToken_WrongSecret(t *testing.T) {
	m := newManager()
	tok, err := m.IssueRefreshToken("user-123")
	require.NoError(t, err)

	m2 := jwtpkg.NewManager(jwtpkg.Config{Secret: []byte("different-secret-padded-to-32by!!")})
	_, err = m2.ParseRefreshToken(tok)
	assert.ErrorIs(t, err, jwtpkg.ErrTokenInvalid)
}
