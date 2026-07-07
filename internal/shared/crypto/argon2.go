// Package crypto provides all cryptographic primitives for GophKeeper.
package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFParams holds the Argon2id parameters stored per-user in the database
// and in the local .gkdb file header.
type KDFParams struct {
	Algo    string `json:"algo"`
	Memory  uint32 `json:"m"`
	Time    uint32 `json:"t"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
}

// DefaultKDFParams returns the recommended production Argon2id parameters.
func DefaultKDFParams() (KDFParams, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, fmt.Errorf("generate salt: %w", err)
	}
	return KDFParams{
		Algo:    "argon2id",
		Memory:  64 * 1024, // 64 MB
		Time:    3,
		Threads: 4,
		Salt:    salt,
	}, nil
}

// DeriveKey runs Argon2id with p and returns a 32-byte master key.
func DeriveKey(password []byte, p KDFParams) []byte {
	return argon2.IDKey(password, p.Salt, p.Time, p.Memory, p.Threads, 32)
}

// MarshalKDFParams serialises KDFParams to JSON for storage.
func MarshalKDFParams(p KDFParams) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal kdf params: %w", err)
	}
	return string(b), nil
}

// UnmarshalKDFParams deserialises KDFParams from JSON.
func UnmarshalKDFParams(s string) (KDFParams, error) {
	var p KDFParams
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return KDFParams{}, fmt.Errorf("unmarshal kdf params: %w", err)
	}
	return p, nil
}
