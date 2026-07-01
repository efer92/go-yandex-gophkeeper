package crypto_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/efremov/gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePassword_DefaultOpts(t *testing.T) {
	opts := crypto.DefaultPasswordOpts()
	pwd, err := crypto.GeneratePassword(opts)
	require.NoError(t, err)
	assert.Len(t, pwd, opts.Length)

	hasUpper := strings.IndexFunc(pwd, unicode.IsUpper) >= 0
	hasDigit := strings.IndexFunc(pwd, unicode.IsDigit) >= 0
	hasSymbol := strings.ContainsAny(pwd, "!@#$%^&*()-_=+[]{}|;:,.<>?")
	assert.True(t, hasUpper, "should contain uppercase")
	assert.True(t, hasDigit, "should contain digit")
	assert.True(t, hasSymbol, "should contain symbol")
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	opts := crypto.DefaultPasswordOpts()
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		p, err := crypto.GeneratePassword(opts)
		require.NoError(t, err)
		assert.False(t, seen[p], "duplicate password generated")
		seen[p] = true
	}
}

func TestGeneratePassword_LengthRespected(t *testing.T) {
	for _, l := range []int{4, 8, 16, 32, 64} {
		opts := crypto.DefaultPasswordOpts()
		opts.Length = l
		p, err := crypto.GeneratePassword(opts)
		require.NoError(t, err)
		assert.Len(t, p, l)
	}
}

func TestGeneratePassword_TooShort(t *testing.T) {
	opts := crypto.DefaultPasswordOpts()
	opts.Length = 3
	_, err := crypto.GeneratePassword(opts)
	assert.Error(t, err)
}

func TestGeneratePassword_NoSymbols(t *testing.T) {
	opts := crypto.PasswordOpts{Length: 20, Upper: true, Digits: true, Symbols: false}
	p, err := crypto.GeneratePassword(opts)
	require.NoError(t, err)
	hasSymbol := strings.ContainsAny(p, "!@#$%^&*")
	assert.False(t, hasSymbol, "should not contain symbols")
}

func TestGeneratePassword_NoAmbiguous(t *testing.T) {
	opts := crypto.PasswordOpts{Length: 200, Upper: true, Digits: true, Symbols: false, NoAmbiguous: true}
	p, err := crypto.GeneratePassword(opts)
	require.NoError(t, err)
	assert.False(t, strings.ContainsAny(p, "l1IO0"), "should not contain ambiguous chars")
}

func TestDerivePassword_Deterministic(t *testing.T) {
	masterKey := make([]byte, 32)
	opts := crypto.DeterministicOpts{
		Realm:        "github.com",
		Length:       20,
		PasswordOpts: crypto.DefaultPasswordOpts(),
	}
	p1, err := crypto.DerivePassword(masterKey, opts)
	require.NoError(t, err)
	p2, err := crypto.DerivePassword(masterKey, opts)
	require.NoError(t, err)
	assert.Equal(t, p1, p2, "same inputs must always produce same password")
}

func TestDerivePassword_DifferentRealms(t *testing.T) {
	masterKey := make([]byte, 32)
	base := crypto.DeterministicOpts{Length: 20, PasswordOpts: crypto.DefaultPasswordOpts()}

	base.Realm = "github.com"
	p1, _ := crypto.DerivePassword(masterKey, base)
	base.Realm = "gitlab.com"
	p2, _ := crypto.DerivePassword(masterKey, base)
	assert.NotEqual(t, p1, p2, "different realms must produce different passwords")
}

func TestDerivePassword_DifferentMasterKeys(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 1
	opts := crypto.DeterministicOpts{Realm: "example.com", Length: 20, PasswordOpts: crypto.DefaultPasswordOpts()}
	p1, _ := crypto.DerivePassword(k1, opts)
	p2, _ := crypto.DerivePassword(k2, opts)
	assert.NotEqual(t, p1, p2)
}

func TestDerivePassword_EmptyRealm(t *testing.T) {
	_, err := crypto.DerivePassword(make([]byte, 32), crypto.DeterministicOpts{Realm: "", Length: 20})
	assert.Error(t, err)
}
