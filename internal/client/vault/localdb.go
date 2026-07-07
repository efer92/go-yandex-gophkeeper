// Package vault manages the local encrypted .gkdb vault file.
package vault

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

const (
	magic   = "GKDB"
	version = uint16(1)
)

// Item is a decrypted vault entry stored locally.
type Item struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Type      string    `json:"type"`
	Payload   []byte    `json:"payload"` // still encrypted with vault sym key
	Metadata  string    `json:"metadata"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VaultData is the plaintext content of the local vault.
type VaultData struct {
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	Items    []Item    `json:"items"`
	SyncedAt time.Time `json:"synced_at"`
}

// LocalDB manages reads and writes of the .gkdb encrypted vault file.
type LocalDB struct {
	path string
}

// NewLocalDB creates a LocalDB for the given path.
func NewLocalDB(path string) *LocalDB {
	return &LocalDB{path: path}
}

// Save encrypts and writes VaultData to the .gkdb file.
// password and optional keyfileData are used to derive the master key.
func (db *LocalDB) Save(data VaultData, password, keyfileData []byte) error {
	kdfParams, err := crypto.DefaultKDFParams()
	if err != nil {
		return fmt.Errorf("generate kdf params: %w", err)
	}
	masterKey := crypto.CompositeKey(password, keyfileData, kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)

	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal vault data: %w", err)
	}

	encBody, err := crypto.Encrypt(encKey, body)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	kdfJSON, err := crypto.MarshalKDFParams(kdfParams)
	if err != nil {
		return fmt.Errorf("marshal kdf params: %w", err)
	}

	// Key check: encrypting a fixed sentinel so we can detect wrong password on open.
	keyCheck, err := crypto.Encrypt(encKey, []byte("gkdb-key-check"))
	if err != nil {
		return fmt.Errorf("encrypt key check: %w", err)
	}

	f, err := os.OpenFile(db.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open vault file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Header: magic(4) + version(2) + kdfJSON length(4) + kdfJSON + keyCheckLen(4) + keyCheck + bodyLen(4) + encBody
	if _, err := f.Write([]byte(magic)); err != nil {
		return err
	}
	if err := binary.Write(f, binary.BigEndian, version); err != nil {
		return err
	}
	kdfBytes := []byte(kdfJSON)
	if len(kdfBytes) > math.MaxUint32 || len(keyCheck) > math.MaxUint32 || len(encBody) > math.MaxUint32 {
		return errors.New("vault data exceeds maximum size")
	}
	if err := binary.Write(f, binary.BigEndian, uint32(len(kdfBytes))); err != nil { // #nosec G115 -- bounds validated before this call
		return err
	}
	if _, err := f.Write(kdfBytes); err != nil {
		return err
	}
	if err := binary.Write(f, binary.BigEndian, uint32(len(keyCheck))); err != nil { // #nosec G115 -- bounds validated before this call
		return err
	}
	if _, err := f.Write(keyCheck); err != nil {
		return err
	}
	if err := binary.Write(f, binary.BigEndian, uint32(len(encBody))); err != nil { // #nosec G115 -- bounds validated before this call
		return err
	}
	_, err = f.Write(encBody)
	return err
}

// Load decrypts and reads VaultData from the .gkdb file.
func (db *LocalDB) Load(password, keyfileData []byte) (VaultData, error) {
	f, err := os.Open(db.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VaultData{}, ErrVaultNotFound
		}
		return VaultData{}, fmt.Errorf("open vault file: %w", err)
	}
	defer func() { _ = f.Close() }()

	magicBuf := make([]byte, 4)
	if _, err := f.Read(magicBuf); err != nil || string(magicBuf) != magic {
		return VaultData{}, ErrInvalidVault
	}

	var ver uint16
	if err := binary.Read(f, binary.BigEndian, &ver); err != nil {
		return VaultData{}, ErrInvalidVault
	}

	var kdfLen uint32
	if err := binary.Read(f, binary.BigEndian, &kdfLen); err != nil {
		return VaultData{}, ErrInvalidVault
	}
	kdfBytes := make([]byte, kdfLen)
	if _, err := f.Read(kdfBytes); err != nil {
		return VaultData{}, ErrInvalidVault
	}
	kdfParams, err := crypto.UnmarshalKDFParams(string(kdfBytes))
	if err != nil {
		return VaultData{}, ErrInvalidVault
	}

	masterKey := crypto.CompositeKey(password, keyfileData, kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)

	var keyCheckLen uint32
	if err := binary.Read(f, binary.BigEndian, &keyCheckLen); err != nil {
		return VaultData{}, ErrInvalidVault
	}
	keyCheck := make([]byte, keyCheckLen)
	if _, err := f.Read(keyCheck); err != nil {
		return VaultData{}, ErrInvalidVault
	}
	if _, err := crypto.Decrypt(encKey, keyCheck); err != nil {
		return VaultData{}, ErrWrongPassword
	}

	var bodyLen uint32
	if err := binary.Read(f, binary.BigEndian, &bodyLen); err != nil {
		return VaultData{}, ErrInvalidVault
	}
	encBody := make([]byte, bodyLen)
	if _, err := f.Read(encBody); err != nil {
		return VaultData{}, ErrInvalidVault
	}

	body, err := crypto.Decrypt(encKey, encBody)
	if err != nil {
		return VaultData{}, ErrWrongPassword
	}

	var data VaultData
	if err := json.Unmarshal(body, &data); err != nil {
		return VaultData{}, fmt.Errorf("unmarshal vault: %w", err)
	}
	return data, nil
}

// Exists returns true if the vault file exists.
func (db *LocalDB) Exists() bool {
	_, err := os.Stat(db.path)
	return err == nil
}

var (
	// ErrVaultNotFound is returned when the .gkdb file does not exist.
	ErrVaultNotFound = errors.New("vault file not found")
	// ErrWrongPassword is returned when decryption fails due to wrong password.
	ErrWrongPassword = errors.New("wrong master password or keyfile")
	// ErrInvalidVault is returned when the .gkdb file is malformed.
	ErrInvalidVault = errors.New("invalid vault file format")
)
