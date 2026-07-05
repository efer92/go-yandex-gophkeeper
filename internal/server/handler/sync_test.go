package handler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/handler"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

func TestNewSyncHandler_NotNil(t *testing.T) {
	store := testutil.NewMockStore()
	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(store, syncSvc)
	h := handler.NewSyncHandler(syncSvc, vaultSvc)
	assert.NotNil(t, h)
}
