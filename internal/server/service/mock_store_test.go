package service_test

import (
	"context"
	"strconv"
	"sync"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
)

// mockStore implements storage.Store for unit tests.
type mockStore struct {
	users    *mockUsers
	sessions *mockSessions
	vault    *mockVault
	mfa      *mockMFA
	audit    *mockAudit
}

func newMockStore() *mockStore {
	return &mockStore{
		users:    &mockUsers{byUsername: make(map[string]storage.User)},
		sessions: &mockSessions{byToken: make(map[string]storage.Session)},
		vault:    &mockVault{items: make(map[string]storage.VaultItem)},
		mfa:      &mockMFA{totps: make(map[string]storage.TOTPRecord)},
		audit:    &mockAudit{},
	}
}

func (m *mockStore) Users() storage.Users       { return m.users }
func (m *mockStore) Sessions() storage.Sessions { return m.sessions }
func (m *mockStore) Vault() storage.Vault       { return m.vault }
func (m *mockStore) MFA() storage.MFA           { return m.mfa }
func (m *mockStore) Audit() storage.Audit       { return m.audit }
func (m *mockStore) Close()                     {}

// mockUsers —————————————————————————————————————

type mockUsers struct {
	mu         sync.Mutex
	byUsername map[string]storage.User
	byID       map[string]storage.User
}

func (m *mockUsers) Create(_ context.Context, u storage.User) (storage.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byUsername[u.Username]; exists {
		return storage.User{}, storage.ErrConflict
	}
	u.ID = "user-" + u.Username
	if m.byID == nil {
		m.byID = make(map[string]storage.User)
	}
	m.byUsername[u.Username] = u
	m.byID[u.ID] = u
	return u, nil
}

func (m *mockUsers) GetByUsername(_ context.Context, username string) (storage.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byUsername[username]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return u, nil
}

func (m *mockUsers) GetByID(_ context.Context, id string) (storage.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return u, nil
}

func (m *mockUsers) SetMFARequired(_ context.Context, userID string, required bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.MFARequired = required
	m.byID[userID] = u
	m.byUsername[u.Username] = u
	return nil
}

// mockSessions —————————————————————————————————————

type mockSessions struct {
	mu      sync.Mutex
	byToken map[string]storage.Session
}

func (m *mockSessions) Create(_ context.Context, s storage.Session) (storage.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.ID = "session-" + s.RefreshToken[:8]
	m.byToken[s.RefreshToken] = s
	return s, nil
}

func (m *mockSessions) GetByRefreshToken(_ context.Context, token string) (storage.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byToken[token]
	if !ok {
		return storage.Session{}, storage.ErrNotFound
	}
	return s, nil
}

func (m *mockSessions) SetMFAVerified(_ context.Context, id string) error { return nil }

func (m *mockSessions) Delete(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byToken, token)
	return nil
}

func (m *mockSessions) DeleteExpired(_ context.Context) error { return nil }

// mockVault —————————————————————————————————————

type mockVault struct {
	mu    sync.Mutex
	items map[string]storage.VaultItem
	seq   int
}

func (m *mockVault) Create(_ context.Context, item storage.VaultItem) (storage.VaultItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	item.ID = "item-" + strconv.Itoa(m.seq)
	item.Version = 1
	m.items[item.ID] = item
	return item, nil
}

func (m *mockVault) Get(_ context.Context, id, userID string) (storage.VaultItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok || item.UserID != userID {
		return storage.VaultItem{}, storage.ErrNotFound
	}
	return item, nil
}

func (m *mockVault) Update(_ context.Context, item storage.VaultItem) (storage.VaultItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.items[item.ID]
	if !ok || existing.UserID != item.UserID {
		return storage.VaultItem{}, storage.ErrNotFound
	}
	existing.Payload = item.Payload
	existing.Metadata = item.Metadata
	existing.Version++
	m.items[item.ID] = existing
	return existing, nil
}

func (m *mockVault) Delete(_ context.Context, id, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok || item.UserID != userID {
		return storage.ErrNotFound
	}
	delete(m.items, id)
	return nil
}

func (m *mockVault) List(_ context.Context, userID string, f storage.ListFilter) ([]storage.VaultItem, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []storage.VaultItem
	for _, item := range m.items {
		if item.UserID == userID {
			result = append(result, item)
		}
	}
	return result, "", nil
}

// mockMFA —————————————————————————————————————

type mockMFA struct {
	mu    sync.Mutex
	totps map[string]storage.TOTPRecord
}

func (m *mockMFA) CreateTOTP(_ context.Context, r storage.TOTPRecord) (storage.TOTPRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.ID = "totp-" + r.UserID
	m.totps[r.ID] = r
	return r, nil
}

func (m *mockMFA) GetTOTPByID(_ context.Context, id, userID string) (storage.TOTPRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.totps[id]
	if !ok || r.UserID != userID {
		return storage.TOTPRecord{}, storage.ErrNotFound
	}
	return r, nil
}

func (m *mockMFA) ConfirmTOTP(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.totps[id]
	r.Confirmed = true
	m.totps[id] = r
	return nil
}

func (m *mockMFA) ListTOTP(_ context.Context, userID string) ([]storage.TOTPRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []storage.TOTPRecord
	for _, r := range m.totps {
		if r.UserID == userID && r.Confirmed {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *mockMFA) CreateWebAuthnCredential(_ context.Context, _ storage.WebAuthnCredential) error {
	return nil
}
func (m *mockMFA) GetWebAuthnCredentials(_ context.Context, _ string) ([]storage.WebAuthnCredential, error) {
	return nil, nil
}
func (m *mockMFA) UpdateWebAuthnSignCount(_ context.Context, _ []byte, _ uint32) error { return nil }
func (m *mockMFA) SaveWebAuthnSession(_ context.Context, _, _ string) (string, error) {
	return "s1", nil
}
func (m *mockMFA) GetWebAuthnSession(_ context.Context, _ string) (string, error) { return "{}", nil }
func (m *mockMFA) DeleteWebAuthnSession(_ context.Context, _ string) error        { return nil }

// mockAudit —————————————————————————————————————

type mockAudit struct {
	mu      sync.Mutex
	entries []storage.AuditEntry
}

func (m *mockAudit) Append(_ context.Context, e storage.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
