package crypto_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey_Raw(t *testing.T) {
	k, err := crypto.GenerateKey(crypto.KeyTypeRaw)
	require.NoError(t, err)
	assert.Equal(t, crypto.KeyTypeRaw, k.Type)
	assert.Len(t, k.PrivateKey, 32)
}

func TestGenerateKey_Ed25519(t *testing.T) {
	k, err := crypto.GenerateKey(crypto.KeyTypeEd25519)
	require.NoError(t, err)
	assertValidPEM(t, k.PrivateKey, "PRIVATE KEY")
	assert.Contains(t, string(k.PublicKey), "ssh-ed25519")
}

func TestGenerateKey_RSA2048(t *testing.T) {
	k, err := crypto.GenerateKey(crypto.KeyTypeRSA2048)
	require.NoError(t, err)
	assertValidPEM(t, k.PrivateKey, "PRIVATE KEY")
	assertValidPEM(t, k.PublicKey, "PUBLIC KEY")

	// Verify it's actually 2048-bit RSA.
	priv := parsePKCS8(t, k.PrivateKey)
	rsaKey, ok := priv.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey, got %T", priv)
	assert.Equal(t, 2048, rsaKey.N.BitLen())
}

func TestGenerateKey_P256(t *testing.T) {
	k, err := crypto.GenerateKey(crypto.KeyTypeP256)
	require.NoError(t, err)
	assertValidPEM(t, k.PrivateKey, "PRIVATE KEY")
	assertValidPEM(t, k.PublicKey, "PUBLIC KEY")
}

func TestGenerateKey_X25519(t *testing.T) {
	k, err := crypto.GenerateKey(crypto.KeyTypeX25519)
	require.NoError(t, err)
	assertValidPEM(t, k.PrivateKey, "PRIVATE KEY")
	assertValidPEM(t, k.PublicKey, "PUBLIC KEY")
}

func TestGenerateKey_Unknown(t *testing.T) {
	_, err := crypto.GenerateKey("banana")
	assert.Error(t, err)
}

func TestGenerateKey_Uniqueness(t *testing.T) {
	k1, _ := crypto.GenerateKey(crypto.KeyTypeEd25519)
	k2, _ := crypto.GenerateKey(crypto.KeyTypeEd25519)
	assert.NotEqual(t, k1.PrivateKey, k2.PrivateKey, "two random keys must differ")
}

func TestDeriveKeyFromMaster_Deterministic(t *testing.T) {
	masterKey := make([]byte, 32)
	for _, kt := range []crypto.KeyType{crypto.KeyTypeRaw, crypto.KeyTypeEd25519, crypto.KeyTypeP256, crypto.KeyTypeX25519} {
		t.Run(string(kt), func(t *testing.T) {
			k1, err := crypto.DeriveKeyFromMaster(masterKey, "github.com", kt)
			require.NoError(t, err)
			k2, err := crypto.DeriveKeyFromMaster(masterKey, "github.com", kt)
			require.NoError(t, err)
			assert.Equal(t, k1.PrivateKey, k2.PrivateKey, "same inputs must produce same key")
		})
	}
}

func TestDeriveKeyFromMaster_DifferentRealms(t *testing.T) {
	masterKey := make([]byte, 32)
	k1, _ := crypto.DeriveKeyFromMaster(masterKey, "github.com", crypto.KeyTypeEd25519)
	k2, _ := crypto.DeriveKeyFromMaster(masterKey, "gitlab.com", crypto.KeyTypeEd25519)
	assert.NotEqual(t, k1.PrivateKey, k2.PrivateKey)
}

func TestDeriveKeyFromMaster_EmptyRealm(t *testing.T) {
	_, err := crypto.DeriveKeyFromMaster(make([]byte, 32), "", crypto.KeyTypeRaw)
	assert.Error(t, err)
}

func TestDeriveKeyFromMaster_Raw(t *testing.T) {
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	k, err := crypto.DeriveKeyFromMaster(masterKey, "prod-db", crypto.KeyTypeRaw)
	require.NoError(t, err)
	assert.Len(t, k.PrivateKey, 32)

	// Deterministic.
	k2, _ := crypto.DeriveKeyFromMaster(masterKey, "prod-db", crypto.KeyTypeRaw)
	assert.Equal(t, k.PrivateKey, k2.PrivateKey)
}

// helpers

func assertValidPEM(t *testing.T, data []byte, expectedType string) {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "expected PEM block")
	assert.Equal(t, expectedType, block.Type)
}

func parsePKCS8(t *testing.T, pemData []byte) any {
	t.Helper()
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}
