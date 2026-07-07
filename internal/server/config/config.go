// Package config loads server configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"time"
)

// Config holds all server runtime configuration.
type Config struct {
	ServerAddr       string
	DatabaseURL      string
	JWTSecret        []byte
	TLSCertFile      string
	TLSKeyFile       string
	LogLevel         string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	WebAuthnRPID     string
	WebAuthnRPOrigin string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	if tlsCertFile == "" {
		return nil, fmt.Errorf("TLS_CERT_FILE is required")
	}
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if tlsKeyFile == "" {
		return nil, fmt.Errorf("TLS_KEY_FILE is required")
	}

	cfg := &Config{
		ServerAddr:       getEnv("SERVER_ADDR", ":50051"),
		DatabaseURL:      dbURL,
		JWTSecret:        []byte(secret),
		TLSCertFile:      tlsCertFile,
		TLSKeyFile:       tlsKeyFile,
		LogLevel:         getEnv("LOG_LEVEL", "info"),
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		WebAuthnRPID:     getEnv("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPOrigin: getEnv("WEBAUTHN_RP_ORIGIN", "https://localhost"),
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
