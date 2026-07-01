package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Charset constants for password generation.
const (
	charsetLower   = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetDigits  = "0123456789"
	charsetSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	charsetAmbig   = "l1IO0" // excluded when NoAmbiguous is set
)

// PasswordOpts controls random password generation.
type PasswordOpts struct {
	Length      int
	Upper       bool
	Digits      bool
	Symbols     bool
	NoAmbiguous bool // exclude visually similar characters (l,1,I,O,0)
}

// DefaultPasswordOpts returns a strong-by-default configuration.
func DefaultPasswordOpts() PasswordOpts {
	return PasswordOpts{
		Length:      20,
		Upper:       true,
		Digits:      true,
		Symbols:     true,
		NoAmbiguous: false,
	}
}

// GeneratePassword creates a cryptographically random password matching opts.
func GeneratePassword(opts PasswordOpts) (string, error) {
	if opts.Length < 4 {
		return "", errors.New("password length must be at least 4")
	}
	charset := charsetLower
	if opts.Upper {
		charset += charsetUpper
	}
	if opts.Digits {
		charset += charsetDigits
	}
	if opts.Symbols {
		charset += charsetSymbols
	}
	if opts.NoAmbiguous {
		var filtered strings.Builder
		for _, c := range charset {
			if !strings.ContainsRune(charsetAmbig, c) {
				filtered.WriteRune(c)
			}
		}
		charset = filtered.String()
	}
	if len(charset) == 0 {
		return "", errors.New("charset is empty — enable at least one character class")
	}

	// Guarantee at least one character from each enabled class.
	// Use filtered variants when NoAmbiguous is set so required chars also obey the filter.
	filterChars := func(s string) string {
		if !opts.NoAmbiguous {
			return s
		}
		var b strings.Builder
		for _, c := range s {
			if !strings.ContainsRune(charsetAmbig, c) {
				b.WriteRune(c)
			}
		}
		return b.String()
	}
	var required []byte
	if cl := filterChars(charsetLower); cl != "" {
		required = append(required, mustRandChar(cl))
	}
	if opts.Upper {
		if cu := filterChars(charsetUpper); cu != "" {
			required = append(required, mustRandChar(cu))
		}
	}
	if opts.Digits {
		if cd := filterChars(charsetDigits); cd != "" {
			required = append(required, mustRandChar(cd))
		}
	}
	if opts.Symbols {
		required = append(required, mustRandChar(charsetSymbols))
	}

	result := make([]byte, opts.Length)
	for i := range result {
		result[i] = mustRandChar(charset)
	}
	// Overwrite the first len(required) positions with guaranteed chars,
	// then shuffle the whole slice with Fisher-Yates.
	copy(result[:len(required)], required)
	if err := shuffle(result); err != nil {
		return "", fmt.Errorf("shuffle: %w", err)
	}
	return string(result), nil
}

func mustRandChar(charset string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return charset[n.Int64()]
}

func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(jBig.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// DeterministicOpts controls gokey-style deterministic derivation.
type DeterministicOpts struct {
	// Realm identifies the credential (e.g. "github.com", "aws-prod").
	Realm string
	// Length is the desired password length.
	Length int
	// PasswordOpts controls the character set applied to the derived bytes.
	PasswordOpts
}

// DerivePassword deterministically generates a password from a master key and a realm.
// The same masterKey + realm always produce the same password; nothing is stored.
// Uses HKDF-SHA256 to stretch masterKey into a biased-free byte stream.
func DerivePassword(masterKey []byte, opts DeterministicOpts) (string, error) {
	if opts.Realm == "" {
		return "", errors.New("realm must not be empty")
	}
	if opts.Length < 4 {
		return "", errors.New("password length must be at least 4")
	}

	charset := charsetLower
	if opts.Upper {
		charset += charsetUpper
	}
	if opts.Digits {
		charset += charsetDigits
	}
	if opts.Symbols {
		charset += charsetSymbols
	}
	if opts.NoAmbiguous {
		var filtered strings.Builder
		for _, c := range charset {
			if !strings.ContainsRune(charsetAmbig, c) {
				filtered.WriteRune(c)
			}
		}
		charset = filtered.String()
	}
	if len(charset) == 0 {
		return "", errors.New("charset is empty")
	}

	// Derive a deterministic byte stream for this realm.
	reader := hkdf.New(sha256.New, masterKey, []byte("gophkeeper-passgen-v1"), []byte(opts.Realm))
	stream := make([]byte, opts.Length*4) // over-allocate to handle rejection sampling
	if _, err := io.ReadFull(reader, stream); err != nil {
		return "", fmt.Errorf("hkdf read: %w", err)
	}

	// Rejection sampling: map each 4-byte chunk to a charset index without modulo bias.
	modLen := uint32(len(charset)) // #nosec G115 -- charset is max ~100 chars, never overflows uint32
	threshold := (^uint32(0) - (^uint32(0))%modLen) + 1

	result := make([]byte, 0, opts.Length)
	for i := 0; len(result) < opts.Length; i++ {
		if i*4+3 >= len(stream) {
			// Refill if needed (very rare with 4x over-allocation).
			reader2 := hkdf.New(sha256.New, masterKey,
				[]byte(fmt.Sprintf("gophkeeper-passgen-v1-refill-%d", i)),
				[]byte(opts.Realm))
			stream = make([]byte, opts.Length*4)
			if _, err := io.ReadFull(reader2, stream); err != nil {
				return "", err
			}
			i = 0
		}
		v := uint32(stream[i*4])<<24 | uint32(stream[i*4+1])<<16 |
			uint32(stream[i*4+2])<<8 | uint32(stream[i*4+3])
		if v >= threshold {
			continue // reject to eliminate modulo bias
		}
		result = append(result, charset[v%modLen])
	}
	return string(result), nil
}
