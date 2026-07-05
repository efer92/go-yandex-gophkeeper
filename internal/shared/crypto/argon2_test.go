package crypto_test

import (
	"testing"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	p := crypto.DefaultKDFParams()
	k1 := crypto.DeriveKey([]byte("password"), p)
	k2 := crypto.DeriveKey([]byte("password"), p)
	assert.Equal(t, k1, k2, "same password+salt must produce same key")
	assert.Len(t, k1, 32)
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	p := crypto.DefaultKDFParams()
	k1 := crypto.DeriveKey([]byte("password1"), p)
	k2 := crypto.DeriveKey([]byte("password2"), p)
	assert.NotEqual(t, k1, k2)
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	p1 := crypto.DefaultKDFParams()
	p2 := crypto.DefaultKDFParams()
	k1 := crypto.DeriveKey([]byte("password"), p1)
	k2 := crypto.DeriveKey([]byte("password"), p2)
	assert.NotEqual(t, k1, k2, "different salts must produce different keys")
}

func TestMarshalUnmarshalKDFParams(t *testing.T) {
	p := crypto.DefaultKDFParams()
	s, err := crypto.MarshalKDFParams(p)
	require.NoError(t, err)

	p2, err := crypto.UnmarshalKDFParams(s)
	require.NoError(t, err)
	assert.Equal(t, p.Memory, p2.Memory)
	assert.Equal(t, p.Time, p2.Time)
	assert.Equal(t, p.Threads, p2.Threads)
	assert.Equal(t, p.Salt, p2.Salt)
}
