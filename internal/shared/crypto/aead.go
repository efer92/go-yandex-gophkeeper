package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrDecryptFailed is returned when authenticated decryption fails,
// typically because the key or ciphertext is wrong.
var ErrDecryptFailed = errors.New("decryption failed: invalid key or corrupted data")

// Encrypt encrypts plaintext with ChaCha20-Poly1305 using the provided 32-byte key.
// Returns [nonce || ciphertext+tag].
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data produced by Encrypt. Returns ErrDecryptFailed on bad key/data.
func Decrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrDecryptFailed
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}
