package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// StretchKey derives a 64-byte stretched key from the 32-byte master key using HKDF-SHA256.
// The first 32 bytes are the encryption key; the last 32 are the MAC key.
func StretchKey(masterKey []byte) (encKey, macKey []byte) {
	h := hkdf.New(sha256.New, masterKey, nil, []byte("gophkeeper-vault-key-stretch-v1"))
	stretched := make([]byte, 64)
	if _, err := io.ReadFull(h, stretched); err != nil {
		panic(fmt.Sprintf("hkdf read failed: %v", err))
	}
	return stretched[:32], stretched[32:]
}

// GenerateVaultSymKey generates a random 32-byte vault symmetric key.
func GenerateVaultSymKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate vault key: %w", err)
	}
	return key, nil
}

// SealVaultSymKey encrypts the vault symmetric key with the stretched enc key (ChaCha20-Poly1305).
func SealVaultSymKey(vaultKey, encKey []byte) ([]byte, error) {
	return Encrypt(encKey, vaultKey)
}

// OpenVaultSymKey decrypts the sealed vault symmetric key using the stretched enc key.
func OpenVaultSymKey(sealed, encKey []byte) ([]byte, error) {
	return Decrypt(encKey, sealed)
}

// CompositeKey derives a master key from a password and an optional keyfile.
// If keyfileData is non-nil, the password is combined with SHA-256(keyfileData).
func CompositeKey(password, keyfileData []byte, p KDFParams) []byte {
	if keyfileData != nil {
		h := sha256.Sum256(keyfileData)
		combined := make([]byte, len(password)+32)
		copy(combined, password)
		copy(combined[len(password):], h[:])
		password = combined
	}
	return DeriveKey(password, p)
}
