// Package jwt provides JWT token issuance and validation for GophKeeper.
package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the custom JWT payload for GophKeeper access tokens.
type Claims struct {
	jwt.RegisteredClaims
	// MFAVerified is true when the session has passed MFA verification.
	MFAVerified bool `json:"mfa,omitempty"`
}

// Config holds JWT signing parameters.
type Config struct {
	Secret          []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig(secret []byte) Config {
	return Config{
		Secret:          secret,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
}

// Manager issues and validates JWTs.
type Manager struct {
	cfg Config
}

// NewManager creates a Manager with the provided config.
func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

// IssueAccessToken creates a signed access token for userID.
func (m *Manager) IssueAccessToken(userID string, mfaVerified bool) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.cfg.AccessTokenTTL)),
		},
		MFAVerified: mfaVerified,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.cfg.Secret)
}

// IssueRefreshToken creates a long-lived signed refresh token for userID.
// The server validates it against the sessions table rather than trusting the signature alone.
func (m *Manager) IssueRefreshToken(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.cfg.RefreshTokenTTL)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.cfg.Secret)
}

// ParseAccessToken validates and parses an access token. Returns ErrTokenExpired or ErrTokenInvalid.
func (m *Manager) ParseAccessToken(tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.cfg.Secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}
	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

// ParseRefreshToken validates and returns the subject (userID) of a refresh token.
func (m *Manager) ParseRefreshToken(tokenStr string) (string, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.cfg.Secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrTokenExpired
		}
		return "", ErrTokenInvalid
	}
	claims, ok := t.Claims.(*jwt.RegisteredClaims)
	if !ok || !t.Valid {
		return "", ErrTokenInvalid
	}
	return claims.Subject, nil
}

var (
	// ErrTokenExpired is returned when a token's expiry has passed.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenInvalid is returned for malformed or tampered tokens.
	ErrTokenInvalid = errors.New("token invalid")
)
