package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/efremov/gophkeeper/internal/shared/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := randomKey(t)
	plaintext := []byte("hello, GophKeeper!")

	ct, err := crypto.Encrypt(key, plaintext)
	require.NoError(t, err)

	pt, err := crypto.Decrypt(key, ct)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key := randomKey(t)
	plaintext := []byte("same plaintext")

	ct1, err := crypto.Encrypt(key, plaintext)
	require.NoError(t, err)
	ct2, err := crypto.Encrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, ct1, ct2, "each encryption must use a unique nonce")
}

func TestDecrypt_WrongKey(t *testing.T) {
	key := randomKey(t)
	ct, err := crypto.Encrypt(key, []byte("secret"))
	require.NoError(t, err)

	_, err = crypto.Decrypt(randomKey(t), ct)
	assert.ErrorIs(t, err, crypto.ErrDecryptFailed)
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := randomKey(t)
	ct, err := crypto.Encrypt(key, []byte("secret"))
	require.NoError(t, err)

	ct[len(ct)-1] ^= 0xff // flip last byte
	_, err = crypto.Decrypt(key, ct)
	assert.ErrorIs(t, err, crypto.ErrDecryptFailed)
}

func TestDecrypt_TooShort(t *testing.T) {
	key := randomKey(t)
	_, err := crypto.Decrypt(key, []byte("short"))
	assert.ErrorIs(t, err, crypto.ErrDecryptFailed)
}
