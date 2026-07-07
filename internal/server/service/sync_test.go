package service_test

import (
	"testing"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncService_SubscribeAndNotify(t *testing.T) {
	svc := service.NewSyncService()
	ch, cancel := svc.Subscribe("user-1")
	defer cancel()

	item := storage.VaultItem{ID: "item-1", UserID: "user-1", Version: 1}
	svc.NotifyUpsert("user-1", item)

	select {
	case evt := <-ch:
		assert.Equal(t, "upsert", evt.Type)
		require.NotNil(t, evt.Item)
		assert.Equal(t, "item-1", evt.Item.ID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for sync event")
	}
}

func TestSyncService_DeleteEvent(t *testing.T) {
	svc := service.NewSyncService()
	ch, cancel := svc.Subscribe("user-2")
	defer cancel()

	svc.NotifyDelete("user-2", "item-42")

	select {
	case evt := <-ch:
		assert.Equal(t, "delete", evt.Type)
		assert.Equal(t, "item-42", evt.DeletedID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delete event")
	}
}

func TestSyncService_MultipleSubscribers(t *testing.T) {
	svc := service.NewSyncService()
	ch1, cancel1 := svc.Subscribe("user-3")
	ch2, cancel2 := svc.Subscribe("user-3")
	defer cancel1()
	defer cancel2()

	item := storage.VaultItem{ID: "item-x"}
	svc.NotifyUpsert("user-3", item)

	for _, ch := range []<-chan service.SyncEvent{ch1, ch2} {
		select {
		case evt := <-ch:
			assert.Equal(t, "upsert", evt.Type)
		case <-time.After(time.Second):
			t.Fatal("timed out — one subscriber missed the event")
		}
	}
}

func TestSyncService_IsolationBetweenUsers(t *testing.T) {
	svc := service.NewSyncService()
	ch, cancel := svc.Subscribe("user-A")
	defer cancel()

	// Notify a different user — user-A's channel should receive nothing.
	svc.NotifyUpsert("user-B", storage.VaultItem{ID: "item-B"})

	select {
	case evt := <-ch:
		t.Fatalf("unexpected event received: %+v", evt)
	case <-time.After(100 * time.Millisecond):
		// Correct: no cross-user leakage.
	}
}

func TestSyncService_CancelRemovesSubscriber(t *testing.T) {
	svc := service.NewSyncService()
	ch, cancel := svc.Subscribe("user-4")
	cancel() // immediately cancel

	// Channel should be closed.
	select {
	case _, open := <-ch:
		assert.False(t, open, "channel should be closed after cancel")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("channel was not closed")
	}
}
