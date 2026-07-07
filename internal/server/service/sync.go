package service

import (
	"sync"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
)

// SyncEvent represents a change pushed to subscribed clients.
type SyncEvent struct {
	Type      string // "upsert" | "delete"
	Item      *storage.VaultItem
	DeletedID string
}

// SyncService maintains per-user subscription channels for real-time sync.
type SyncService struct {
	mu          sync.RWMutex
	subscribers map[string][]chan SyncEvent // keyed by userID
}

// NewSyncService creates a SyncService.
func NewSyncService() *SyncService {
	return &SyncService{subscribers: make(map[string][]chan SyncEvent)}
}

// Subscribe registers a new subscriber channel for userID and returns a cleanup function.
func (s *SyncService) Subscribe(userID string) (<-chan SyncEvent, func()) {
	ch := make(chan SyncEvent, 32)
	s.mu.Lock()
	s.subscribers[userID] = append(s.subscribers[userID], ch)
	s.mu.Unlock()

	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		subs := s.subscribers[userID]
		for i, c := range subs {
			if c == ch {
				s.subscribers[userID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		close(ch)
	}
}

// NotifyUpsert pushes an upsert event to all subscribers of userID.
func (s *SyncService) NotifyUpsert(userID string, item storage.VaultItem) {
	s.notify(userID, SyncEvent{Type: "upsert", Item: &item})
}

// NotifyDelete pushes a delete event to all subscribers of userID.
func (s *SyncService) NotifyDelete(userID, itemID string) {
	s.notify(userID, SyncEvent{Type: "delete", DeletedID: itemID})
}

func (s *SyncService) notify(userID string, evt SyncEvent) {
	s.mu.RLock()
	subs := s.subscribers[userID]
	s.mu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- evt:
		default: // subscriber too slow; drop to avoid blocking
		}
	}
}
