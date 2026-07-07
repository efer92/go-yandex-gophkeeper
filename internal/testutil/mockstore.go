// Package testutil provides shared test helpers and mock implementations for GophKeeper tests.
package testutil

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
)

// NewTestJWT builds a JWT manager with a short TTL suitable for unit tests.
func NewTestJWT() *jwtpkg.Manager {
	return jwtpkg.NewManager(jwtpkg.Config{
		Secret:          []byte("test-secret-padded-to-32-bytes!!"),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	})
}

// MockStore implements storage.Store using in-memory maps.
// All sub-stores are safe for concurrent use.
type MockStore struct {
	MockUsers    *MockUsers
	MockSessions *MockSessions
	MockVault    *MockVault
	MockMFA      *MockMFA
	MockAudit    *MockAudit
}

// NewMockStore creates a fully initialised MockStore.
func NewMockStore() *MockStore {
	return &MockStore{
		MockUsers:    &MockUsers{ByUsername: make(map[string]storage.User), ByID: make(map[string]storage.User)},
		MockSessions: &MockSessions{ByToken: make(map[string]storage.Session)},
		MockVault:    &MockVault{Items: make(map[string]storage.VaultItem)},
		MockMFA:      &MockMFA{TOTPs: make(map[string]storage.TOTPRecord)},
		MockAudit:    &MockAudit{},
	}
}

// Users satisfies storage.Store.
func (m *MockStore) Users() storage.Users { return m.MockUsers }

// Sessions satisfies storage.Store.
func (m *MockStore) Sessions() storage.Sessions { return m.MockSessions }

// Vault satisfies storage.Store.
func (m *MockStore) Vault() storage.Vault { return m.MockVault }

// MFA satisfies storage.Store.
func (m *MockStore) MFA() storage.MFA { return m.MockMFA }

// Audit satisfies storage.Store.
func (m *MockStore) Audit() storage.Audit { return m.MockAudit }

// Close satisfies storage.Store.
func (m *MockStore) Close() {}

// ── MockUsers ─────────────────────────────────────────────────────────────────

// MockUsers is a thread-safe in-memory implementation of storage.Users.
type MockUsers struct {
	mu         sync.Mutex
	ByUsername map[string]storage.User
	ByID       map[string]storage.User
}

// Create stores a new user, returning ErrConflict on duplicate username.
func (m *MockUsers) Create(_ context.Context, u storage.User) (storage.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.ByUsername[u.Username]; exists {
		return storage.User{}, storage.ErrConflict
	}
	u.ID = "user-" + u.Username
	m.ByUsername[u.Username] = u
	m.ByID[u.ID] = u
	return u, nil
}

// GetByUsername returns the user with the given username.
func (m *MockUsers) GetByUsername(_ context.Context, username string) (storage.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.ByUsername[username]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return u, nil
}

// GetByID returns the user with the given ID.
func (m *MockUsers) GetByID(_ context.Context, id string) (storage.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.ByID[id]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return u, nil
}

// SetMFARequired updates the MFA-required flag for a user.
func (m *MockUsers) SetMFARequired(_ context.Context, userID string, required bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.ByID[userID]
	u.MFARequired = required
	m.ByID[userID] = u
	m.ByUsername[u.Username] = u
	return nil
}

// ── MockSessions ──────────────────────────────────────────────────────────────

// MockSessions is a thread-safe in-memory implementation of storage.Sessions.
type MockSessions struct {
	mu      sync.Mutex
	ByToken map[string]storage.Session
}

// Create stores a session keyed by refresh token.
func (m *MockSessions) Create(_ context.Context, s storage.Session) (storage.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.ID = "session-" + s.RefreshToken[:8]
	m.ByToken[s.RefreshToken] = s
	return s, nil
}

// GetByRefreshToken returns the session for the given token.
func (m *MockSessions) GetByRefreshToken(_ context.Context, token string) (storage.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.ByToken[token]
	if !ok {
		return storage.Session{}, storage.ErrNotFound
	}
	return s, nil
}

// SetMFAVerified marks a session as MFA-verified (no-op in mock).
func (m *MockSessions) SetMFAVerified(_ context.Context, _ string) error { return nil }

// Delete removes the session associated with the refresh token.
func (m *MockSessions) Delete(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ByToken, token)
	return nil
}

// DeleteExpired is a no-op in the mock.
func (m *MockSessions) DeleteExpired(_ context.Context) error { return nil }

// ── MockVault ─────────────────────────────────────────────────────────────────

// MockVault is a thread-safe in-memory implementation of storage.Vault.
type MockVault struct {
	mu    sync.Mutex
	Items map[string]storage.VaultItem
	Seq   int
}

// Create stores a new vault item, assigning a sequential ID.
func (m *MockVault) Create(_ context.Context, item storage.VaultItem) (storage.VaultItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Seq++
	item.ID = "item-" + strconv.Itoa(m.Seq)
	item.Version = 1
	m.Items[item.ID] = item
	return item, nil
}

// Get returns the item if it exists and belongs to userID.
func (m *MockVault) Get(_ context.Context, id, userID string) (storage.VaultItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.Items[id]
	if !ok || item.UserID != userID {
		return storage.VaultItem{}, storage.ErrNotFound
	}
	return item, nil
}

// Update replaces payload/metadata and increments the version.
func (m *MockVault) Update(_ context.Context, item storage.VaultItem) (storage.VaultItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.Items[item.ID]
	if !ok || existing.UserID != item.UserID {
		return storage.VaultItem{}, storage.ErrNotFound
	}
	existing.Payload = item.Payload
	existing.Metadata = item.Metadata
	existing.Version++
	m.Items[item.ID] = existing
	return existing, nil
}

// Delete removes the item if it belongs to userID.
func (m *MockVault) Delete(_ context.Context, id, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.Items[id]
	if !ok || item.UserID != userID {
		return storage.ErrNotFound
	}
	delete(m.Items, id)
	return nil
}

// List returns all items owned by userID.
func (m *MockVault) List(_ context.Context, userID string, _ storage.ListFilter) ([]storage.VaultItem, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []storage.VaultItem
	for _, item := range m.Items {
		if item.UserID == userID {
			result = append(result, item)
		}
	}
	return result, "", nil
}

// ── MockMFA ───────────────────────────────────────────────────────────────────

// MockMFA is a thread-safe in-memory implementation of storage.MFA.
type MockMFA struct {
	mu    sync.Mutex
	TOTPs map[string]storage.TOTPRecord
}

// CreateTOTP stores a new TOTP record.
func (m *MockMFA) CreateTOTP(_ context.Context, r storage.TOTPRecord) (storage.TOTPRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.ID = "totp-" + r.UserID
	m.TOTPs[r.ID] = r
	return r, nil
}

// GetTOTPByID retrieves a TOTP record by ID and userID.
func (m *MockMFA) GetTOTPByID(_ context.Context, id, userID string) (storage.TOTPRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.TOTPs[id]
	if !ok || r.UserID != userID {
		return storage.TOTPRecord{}, storage.ErrNotFound
	}
	return r, nil
}

// ConfirmTOTP marks a TOTP record as confirmed.
func (m *MockMFA) ConfirmTOTP(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.TOTPs[id]
	r.Confirmed = true
	m.TOTPs[id] = r
	return nil
}

// ListTOTP returns confirmed TOTP records for a user.
func (m *MockMFA) ListTOTP(_ context.Context, userID string) ([]storage.TOTPRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []storage.TOTPRecord
	for _, r := range m.TOTPs {
		if r.UserID == userID && r.Confirmed {
			out = append(out, r)
		}
	}
	return out, nil
}

// CreateWebAuthnCredential is a no-op stub.
func (m *MockMFA) CreateWebAuthnCredential(_ context.Context, _ storage.WebAuthnCredential) error {
	return nil
}

// GetWebAuthnCredentials returns an empty slice.
func (m *MockMFA) GetWebAuthnCredentials(_ context.Context, _ string) ([]storage.WebAuthnCredential, error) {
	return nil, nil
}

// UpdateWebAuthnSignCount is a no-op stub.
func (m *MockMFA) UpdateWebAuthnSignCount(_ context.Context, _ []byte, _ uint32) error { return nil }

// SaveWebAuthnSession stores a WebAuthn challenge session.
func (m *MockMFA) SaveWebAuthnSession(_ context.Context, _, _ string) (string, error) {
	return "s1", nil
}

// GetWebAuthnSession retrieves a WebAuthn challenge session.
func (m *MockMFA) GetWebAuthnSession(_ context.Context, _ string) (string, error) { return "{}", nil }

// DeleteWebAuthnSession removes a WebAuthn challenge session.
func (m *MockMFA) DeleteWebAuthnSession(_ context.Context, _ string) error { return nil }

// ── MockAudit ─────────────────────────────────────────────────────────────────

// MockAudit is a thread-safe in-memory implementation of storage.Audit.
type MockAudit struct {
	mu      sync.Mutex
	Entries []storage.AuditEntry
}

// Append records an audit entry.
func (m *MockAudit) Append(_ context.Context, e storage.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Entries = append(m.Entries, e)
	return nil
}
