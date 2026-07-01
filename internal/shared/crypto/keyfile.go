package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
)

// GenerateKeyfile writes 64 random bytes to path and returns the content.
// The keyfile acts as a second factor for the local .gkdb vault.
func GenerateKeyfile(path string) ([]byte, error) {
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("generate keyfile data: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write keyfile: %w", err)
	}
	return data, nil
}

// LoadKeyfile reads keyfile bytes from path.
func LoadKeyfile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is user-provided; this is the intended behavior of a keyfile loader
	if err != nil {
		return nil, fmt.Errorf("read keyfile %q: %w", path, err)
	}
	return data, nil
}
