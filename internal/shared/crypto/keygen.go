package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

// KeyType enumerates supported key types.
type KeyType string

const (
	KeyTypeRaw     KeyType = "raw"     // 32-byte symmetric key (hex)
	KeyTypeEd25519 KeyType = "ed25519" // Ed25519 SSH key pair
	KeyTypeRSA2048 KeyType = "rsa2048" // RSA 2048-bit key pair
	KeyTypeRSA4096 KeyType = "rsa4096" // RSA 4096-bit key pair
	KeyTypeP256    KeyType = "p256"    // ECDSA P-256 key pair
	KeyTypeP384    KeyType = "p384"    // ECDSA P-384 key pair
	KeyTypeX25519  KeyType = "x25519"  // X25519 Diffie-Hellman key pair
)

// GeneratedKey holds a key pair in PEM (or raw hex) format.
type GeneratedKey struct {
	Type       KeyType
	PrivateKey []byte // PEM-encoded private key (or raw bytes for KeyTypeRaw)
	PublicKey  []byte // PEM-encoded public key or SSH authorized_keys line
}

// GenerateKey creates a random key of the given type using crypto/rand.
func GenerateKey(keyType KeyType) (GeneratedKey, error) {
	switch keyType {
	case KeyTypeRaw:
		return generateRaw(rand.Reader)
	case KeyTypeEd25519:
		return generateEd25519(rand.Reader)
	case KeyTypeRSA2048:
		return generateRSA(2048)
	case KeyTypeRSA4096:
		return generateRSA(4096)
	case KeyTypeP256:
		return generateECDSA(elliptic.P256())
	case KeyTypeP384:
		return generateECDSA(elliptic.P384())
	case KeyTypeX25519:
		return generateX25519(rand.Reader)
	default:
		return GeneratedKey{}, fmt.Errorf("unknown key type: %s", keyType)
	}
}

// DeriveKeyFromMaster deterministically derives a key of the given type from masterKey + realm.
// The same masterKey + realm always produce the same key; nothing is stored.
func DeriveKeyFromMaster(masterKey []byte, realm string, keyType KeyType) (GeneratedKey, error) {
	if realm == "" {
		return GeneratedKey{}, errors.New("realm must not be empty")
	}
	// Derive a deterministic byte stream using HKDF.
	reader := hkdf.New(sha256.New, masterKey,
		[]byte("gophkeeper-keygen-v1"),
		[]byte(string(keyType)+":"+realm))

	switch keyType {
	case KeyTypeRaw:
		return generateRaw(reader)
	case KeyTypeEd25519:
		return generateEd25519(reader)
	case KeyTypeP256:
		return deriveECDSAP256(reader)
	case KeyTypeX25519:
		return generateX25519(reader)
	case KeyTypeRSA2048, KeyTypeRSA4096:
		// RSA generation is computationally expensive; use a seeded reader.
		bits := 2048
		if keyType == KeyTypeRSA4096 {
			bits = 4096
		}
		return generateRSAFromReader(reader, bits)
	default:
		return GeneratedKey{}, fmt.Errorf("unsupported deterministic key type: %s", keyType)
	}
}

func generateRaw(r io.Reader) (GeneratedKey, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return GeneratedKey{}, fmt.Errorf("generate raw key: %w", err)
	}
	return GeneratedKey{Type: KeyTypeRaw, PrivateKey: key, PublicKey: nil}, nil
}

func generateEd25519(r io.Reader) (GeneratedKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return GeneratedKey{}, fmt.Errorf("read seed: %w", err)
	}
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	privPEM, err := marshalEd25519Private(privKey)
	if err != nil {
		return GeneratedKey{}, err
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("ssh public key: %w", err)
	}
	return GeneratedKey{
		Type:       KeyTypeEd25519,
		PrivateKey: privPEM,
		PublicKey:  ssh.MarshalAuthorizedKey(sshPub),
	}, nil
}

func marshalEd25519Private(key ed25519.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

func generateRSA(bits int) (GeneratedKey, error) {
	return generateRSAFromReader(rand.Reader, bits)
}

func generateRSAFromReader(r io.Reader, bits int) (GeneratedKey, error) {
	privKey, err := rsa.GenerateKey(r, bits)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("generate rsa-%d: %w", bits, err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal rsa private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal rsa public: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kt := KeyTypeRSA2048
	if bits == 4096 {
		kt = KeyTypeRSA4096
	}
	return GeneratedKey{Type: kt, PrivateKey: privPEM, PublicKey: pubPEM}, nil
}

// deriveECDSAP256 deterministically derives a P-256 key pair from the byte stream.
// ecdsa.GenerateKey does not guarantee stable output for a given reader, so the
// private scalar is read directly from the stream and validated via crypto/ecdh
// (rejection sampling: out-of-range scalars are skipped and the next block is read).
func deriveECDSAP256(r io.Reader) (GeneratedKey, error) {
	buf := make([]byte, 32)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return GeneratedKey{}, fmt.Errorf("read p256 scalar: %w", err)
		}
		privKey, err := ecdh.P256().NewPrivateKey(buf)
		if err != nil {
			continue // scalar outside [1, N-1]; take the next stream block
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return GeneratedKey{}, fmt.Errorf("marshal p256 private: %w", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(privKey.PublicKey())
		if err != nil {
			return GeneratedKey{}, fmt.Errorf("marshal p256 public: %w", err)
		}
		return GeneratedKey{
			Type:       KeyTypeP256,
			PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
			PublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		}, nil
	}
}

func generateECDSA(curve elliptic.Curve) (GeneratedKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("generate ecdsa: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal ecdsa private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal ecdsa public: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kt := KeyTypeP256
	if curve == elliptic.P384() {
		kt = KeyTypeP384
	}
	return GeneratedKey{Type: kt, PrivateKey: privPEM, PublicKey: pubPEM}, nil
}

func generateX25519(r io.Reader) (GeneratedKey, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(r, seed); err != nil {
		return GeneratedKey{}, fmt.Errorf("x25519 seed: %w", err)
	}
	privKey, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("x25519 private key: %w", err)
	}
	pubKey := privKey.PublicKey()

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal x25519 private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal x25519 public: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return GeneratedKey{Type: KeyTypeX25519, PrivateKey: privPEM, PublicKey: pubPEM}, nil
}
