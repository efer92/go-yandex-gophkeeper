package service

import (
	"context"
	"fmt"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/audit"
)

// VaultService provides zero-knowledge CRUD — it passes encrypted payloads through unchanged.
type VaultService struct {
	store   storage.Store
	syncSvc *SyncService
}

// NewVaultService creates a VaultService.
func NewVaultService(store storage.Store, syncSvc *SyncService) *VaultService {
	return &VaultService{store: store, syncSvc: syncSvc}
}

// Create stores a new encrypted vault item and notifies sync subscribers.
func (s *VaultService) Create(ctx context.Context, userID, itemType string, payload []byte, metadata string) (storage.VaultItem, error) {
	item, err := s.store.Vault().Create(ctx, storage.VaultItem{
		UserID:   userID,
		Type:     itemType,
		Payload:  payload,
		Metadata: metadata,
	})
	if err != nil {
		return storage.VaultItem{}, fmt.Errorf("vault create: %w", err)
	}
	s.logAudit(ctx, userID, audit.ActionVaultCreate, map[string]any{
		"item_id":  item.ID,
		"type":     itemType,
		"metadata": metadata,
	})
	s.syncSvc.NotifyUpsert(userID, item)
	return item, nil
}

// Get retrieves a vault item, enforcing ownership.
func (s *VaultService) Get(ctx context.Context, id, userID string) (storage.VaultItem, error) {
	item, err := s.store.Vault().Get(ctx, id, userID)
	if err != nil {
		return storage.VaultItem{}, err
	}
	s.logAudit(ctx, userID, audit.ActionVaultRead, map[string]any{
		"item_id":  id,
		"metadata": item.Metadata,
	})
	return item, nil
}

// Update modifies payload/metadata of an existing item.
func (s *VaultService) Update(ctx context.Context, id, userID string, payload []byte, metadata string) (storage.VaultItem, error) {
	item, err := s.store.Vault().Update(ctx, storage.VaultItem{
		ID:       id,
		UserID:   userID,
		Payload:  payload,
		Metadata: metadata,
	})
	if err != nil {
		return storage.VaultItem{}, fmt.Errorf("vault update: %w", err)
	}
	s.logAudit(ctx, userID, audit.ActionVaultUpdate, map[string]any{
		"item_id":  id,
		"metadata": metadata,
	})
	s.syncSvc.NotifyUpsert(userID, item)
	return item, nil
}

// Delete removes a vault item and notifies sync subscribers.
func (s *VaultService) Delete(ctx context.Context, id, userID string) error {
	if err := s.store.Vault().Delete(ctx, id, userID); err != nil {
		return err
	}
	s.logAudit(ctx, userID, audit.ActionVaultDelete, map[string]any{
		"item_id": id,
	})
	s.syncSvc.NotifyDelete(userID, id)
	return nil
}

// List returns paginated vault items for the user.
func (s *VaultService) List(ctx context.Context, userID string, f storage.ListFilter) ([]storage.VaultItem, string, error) {
	items, cursor, err := s.store.Vault().List(ctx, userID, f)
	if err != nil {
		return nil, "", err
	}
	s.logAudit(ctx, userID, audit.ActionVaultList, map[string]any{
		"count": len(items),
	})
	return items, cursor, nil
}

func (s *VaultService) logAudit(ctx context.Context, userID string, action audit.Action, detail map[string]any) {
	e := audit.New(userID, action, audit.ResultOK)
	_ = s.store.Audit().Append(ctx, storage.AuditEntry{
		UserID:    e.UserID,
		Action:    string(e.Action),
		Result:    string(e.Result),
		IP:        peerIP(ctx),
		Detail:    detail,
		CreatedAt: e.CreatedAt,
	})
}
