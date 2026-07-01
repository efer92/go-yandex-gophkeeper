package crypto_test

import (
	"testing"

	"github.com/efremov/gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStretchKey_Length(t *testing.T) {
	masterKey := make([]byte, 32)
	enc, mac := crypto.StretchKey(masterKey)
	assert.Len(t, enc, 32)
	assert.Len(t, mac, 32)
	assert.NotEqual(t, enc, mac, "enc and mac keys must differ")
}

func TestStretchKey_Deterministic(t *testing.T) {
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	enc1, mac1 := crypto.StretchKey(masterKey)
	enc2, mac2 := crypto.StretchKey(masterKey)
	assert.Equal(t, enc1, enc2)
	assert.Equal(t, mac1, mac2)
}

func TestSealOpenVaultSymKey_RoundTrip(t *testing.T) {
	vaultKey, err := crypto.GenerateVaultSymKey()
	require.NoError(t, err)

	p := crypto.DefaultKDFParams()
	masterKey := crypto.DeriveKey([]byte("master-password"), p)
	encKey, _ := crypto.StretchKey(masterKey)

	sealed, err := crypto.SealVaultSymKey(vaultKey, encKey)
	require.NoError(t, err)

	opened, err := crypto.OpenVaultSymKey(sealed, encKey)
	require.NoError(t, err)
	assert.Equal(t, vaultKey, opened)
}

func TestOpenVaultSymKey_WrongKey(t *testing.T) {
	vaultKey, err := crypto.GenerateVaultSymKey()
	require.NoError(t, err)

	encKey := make([]byte, 32)
	sealed, err := crypto.SealVaultSymKey(vaultKey, encKey)
	require.NoError(t, err)

	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	_, err = crypto.OpenVaultSymKey(sealed, wrongKey)
	assert.ErrorIs(t, err, crypto.ErrDecryptFailed)
}

func TestCompositeKey_WithKeyfile(t *testing.T) {
	p := crypto.DefaultKDFParams()
	password := []byte("pass")
	keyfile := []byte("keyfile-content")

	k1 := crypto.CompositeKey(password, keyfile, p)
	k2 := crypto.CompositeKey(password, nil, p)
	k3 := crypto.CompositeKey(password, keyfile, p)

	assert.NotEqual(t, k1, k2, "with and without keyfile must differ")
	assert.Equal(t, k1, k3, "same inputs must produce same key")
}
