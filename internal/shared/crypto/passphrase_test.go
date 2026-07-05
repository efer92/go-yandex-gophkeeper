package crypto_test

import (
	"strings"
	"testing"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPassphraseOpts(t *testing.T) {
	opts := crypto.DefaultPassphraseOpts()
	assert.Equal(t, 5, opts.Words)
	assert.Equal(t, "-", opts.Separator)
	assert.True(t, opts.Capitalize)
	assert.True(t, opts.IncludeNum)
}

func TestGeneratePassphrase_WordCount(t *testing.T) {
	opts := crypto.DefaultPassphraseOpts()
	opts.IncludeNum = false
	p, err := crypto.GeneratePassphrase(opts)
	require.NoError(t, err)
	parts := strings.Split(p, opts.Separator)
	assert.Len(t, parts, opts.Words)
}

func TestGeneratePassphrase_WithNumber(t *testing.T) {
	opts := crypto.DefaultPassphraseOpts()
	opts.IncludeNum = true
	p, err := crypto.GeneratePassphrase(opts)
	require.NoError(t, err)
	// last segment should be a 4-digit number (1000-9999)
	parts := strings.Split(p, opts.Separator)
	last := parts[len(parts)-1]
	assert.Len(t, last, 4, "number segment should be 4 digits")
}

func TestGeneratePassphrase_Capitalize(t *testing.T) {
	opts := crypto.DefaultPassphraseOpts()
	opts.IncludeNum = false
	opts.Capitalize = true
	p, err := crypto.GeneratePassphrase(opts)
	require.NoError(t, err)
	parts := strings.Split(p, opts.Separator)
	for _, w := range parts {
		if len(w) > 0 {
			assert.True(t, w[0] >= 'A' && w[0] <= 'Z', "word %q should be capitalized", w)
		}
	}
}

func TestGeneratePassphrase_CustomSeparator(t *testing.T) {
	opts := crypto.DefaultPassphraseOpts()
	opts.Separator = "."
	opts.IncludeNum = false
	p, err := crypto.GeneratePassphrase(opts)
	require.NoError(t, err)
	assert.Contains(t, p, ".", "separator must appear in passphrase")
}

func TestGeneratePassphrase_MinWordCount(t *testing.T) {
	// Words < 2 should be clamped to 2
	opts := crypto.PassphraseOpts{Words: 0, Separator: "-", IncludeNum: false}
	p, err := crypto.GeneratePassphrase(opts)
	require.NoError(t, err)
	parts := strings.Split(p, "-")
	assert.GreaterOrEqual(t, len(parts), 2)
}

func TestGeneratePassphrase_Uniqueness(t *testing.T) {
	opts := crypto.DefaultPassphraseOpts()
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		p, err := crypto.GeneratePassphrase(opts)
		require.NoError(t, err)
		assert.False(t, seen[p], "duplicate passphrase generated")
		seen[p] = true
	}
}
