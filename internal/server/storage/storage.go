// Package storage defines the persistence interfaces for GophKeeper server.
package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a unique constraint is violated.
var ErrConflict = errors.New("conflict")

// User represents a registered account.
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	VaultSymKey  []byte
	KDFParams    string
	MFARequired  bool
	CreatedAt    time.Time
}

// Session represents an active refresh token.
type Session struct {
	ID           string
	UserID       string
	RefreshToken string
	ExpiresAt    time.Time
	MFAVerified  bool
	CreatedAt    time.Time
}

// VaultItem is a stored encrypted vault entry.
type VaultItem struct {
	ID        string
	UserID    string
	Type      string
	Payload   []byte
	Metadata  string
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TOTPRecord stores an enrolled (and possibly confirmed) TOTP credential.
type TOTPRecord struct {
	ID        string
	UserID    string
	Secret    string
	Label     string
	Confirmed bool
	CreatedAt time.Time
}

// WebAuthnCredential stores a registered FIDO2 credential.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	AAGUID       []byte
	SignCount    uint32
	Name         string
	CreatedAt    time.Time
}

// AuditEntry is a single immutable audit log record.
type AuditEntry struct {
	UserID    string
	Action    string
	IP        string
	UserAgent string
	Result    string
	Detail    map[string]any
	CreatedAt time.Time
}

// ListFilter holds optional filtering for vault list queries.
type ListFilter struct {
	TypeFilter string
	Limit      int
	Cursor     string
}

// Users is the persistence interface for user accounts.
type Users interface {
	Create(ctx context.Context, u User) (User, error)
	GetByUsername(ctx context.Context, username string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
	SetMFARequired(ctx context.Context, userID string, required bool) error
}

// Sessions is the persistence interface for refresh token sessions.
type Sessions interface {
	Create(ctx context.Context, s Session) (Session, error)
	GetByRefreshToken(ctx context.Context, token string) (Session, error)
	SetMFAVerified(ctx context.Context, sessionID string) error
	Delete(ctx context.Context, refreshToken string) error
	DeleteExpired(ctx context.Context) error
}

// Vault is the persistence interface for encrypted vault items.
type Vault interface {
	Create(ctx context.Context, item VaultItem) (VaultItem, error)
	Get(ctx context.Context, id, userID string) (VaultItem, error)
	Update(ctx context.Context, item VaultItem) (VaultItem, error)
	Delete(ctx context.Context, id, userID string) error
	List(ctx context.Context, userID string, f ListFilter) ([]VaultItem, string, error)
}

// MFA is the persistence interface for TOTP and WebAuthn credentials.
type MFA interface {
	CreateTOTP(ctx context.Context, r TOTPRecord) (TOTPRecord, error)
	GetTOTPByID(ctx context.Context, id, userID string) (TOTPRecord, error)
	ConfirmTOTP(ctx context.Context, id string) error
	ListTOTP(ctx context.Context, userID string) ([]TOTPRecord, error)

	CreateWebAuthnCredential(ctx context.Context, c WebAuthnCredential) error
	GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	UpdateWebAuthnSignCount(ctx context.Context, credID []byte, signCount uint32) error

	SaveWebAuthnSession(ctx context.Context, userID, data string) (string, error)
	GetWebAuthnSession(ctx context.Context, sessionID string) (string, error)
	DeleteWebAuthnSession(ctx context.Context, sessionID string) error
}

// Audit is the persistence interface for the append-only audit log.
type Audit interface {
	Append(ctx context.Context, e AuditEntry) error
}

// Store aggregates all sub-interfaces behind a single dependency.
type Store interface {
	Users() Users
	Sessions() Sessions
	Vault() Vault
	MFA() MFA
	Audit() Audit
	Close()
}
