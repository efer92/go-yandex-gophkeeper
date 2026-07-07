package handler_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/handler"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

func newVaultHandler() (*handler.VaultHandler, *testutil.MockStore) {
	store := testutil.NewMockStore()
	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(store, syncSvc)
	return handler.NewVaultHandler(vaultSvc), store
}

func ctxWithUser(userID string) context.Context {
	return middleware.ContextWithUserID(context.Background(), userID)
}

func TestVaultHandler_CreateItem_Success(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	resp, err := h.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
		Type:     commonpb.ItemType_CREDENTIAL,
		Payload:  []byte("encrypted"),
		Metadata: "GitHub",
	}.Build())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetItem().GetId())
	assert.Equal(t, "GitHub", resp.GetItem().GetMetadata())
	assert.Equal(t, commonpb.ItemType_CREDENTIAL, resp.GetItem().GetType())
}

func TestVaultHandler_CreateItem_Unauthenticated(t *testing.T) {
	h, _ := newVaultHandler()
	_, err := h.CreateItem(context.Background(), vaultpb.CreateItemRequest_builder{
		Type:    commonpb.ItemType_TEXT,
		Payload: []byte("data"),
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestVaultHandler_CreateItem_AllTypes(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-bob")

	types := []commonpb.ItemType{
		commonpb.ItemType_CREDENTIAL,
		commonpb.ItemType_TEXT,
		commonpb.ItemType_BINARY,
		commonpb.ItemType_CARD,
		commonpb.ItemType_OTP,
	}
	for _, tp := range types {
		resp, err := h.CreateItem(ctx, vaultpb.CreateItemRequest_builder{Type: tp, Payload: []byte("x")}.Build())
		require.NoError(t, err, "type: %v", tp)
		assert.Equal(t, tp, resp.GetItem().GetType())
	}
}

func TestVaultHandler_GetItem_Success(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	created, err := h.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
		Type:    commonpb.ItemType_TEXT,
		Payload: []byte("secret note"),
	}.Build())
	require.NoError(t, err)

	resp, err := h.GetItem(ctx, vaultpb.GetItemRequest_builder{Id: created.GetItem().GetId()}.Build())
	require.NoError(t, err)
	assert.Equal(t, created.GetItem().GetId(), resp.GetItem().GetId())
}

func TestVaultHandler_GetItem_NotFound(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	_, err := h.GetItem(ctx, vaultpb.GetItemRequest_builder{Id: "nonexistent"}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVaultHandler_GetItem_WrongUser(t *testing.T) {
	h, _ := newVaultHandler()

	created, _ := h.CreateItem(ctxWithUser("alice"), vaultpb.CreateItemRequest_builder{
		Payload: []byte("alice's secret"),
	}.Build())

	_, err := h.GetItem(ctxWithUser("bob"), vaultpb.GetItemRequest_builder{Id: created.GetItem().GetId()}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVaultHandler_UpdateItem_Success(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	created, _ := h.CreateItem(ctx, vaultpb.CreateItemRequest_builder{Payload: []byte("old")}.Build())

	resp, err := h.UpdateItem(ctx, vaultpb.UpdateItemRequest_builder{
		Id:       created.GetItem().GetId(),
		Payload:  []byte("new"),
		Metadata: "updated",
	}.Build())
	require.NoError(t, err)
	assert.Equal(t, int64(2), resp.GetItem().GetVersion())
	assert.Equal(t, "updated", resp.GetItem().GetMetadata())
}

func TestVaultHandler_UpdateItem_NotFound(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	_, err := h.UpdateItem(ctx, vaultpb.UpdateItemRequest_builder{Id: "ghost", Payload: []byte("x")}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVaultHandler_DeleteItem_Success(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	created, _ := h.CreateItem(ctx, vaultpb.CreateItemRequest_builder{Payload: []byte("bye")}.Build())

	_, err := h.DeleteItem(ctx, vaultpb.DeleteItemRequest_builder{Id: created.GetItem().GetId()}.Build())
	require.NoError(t, err)

	_, err = h.GetItem(ctx, vaultpb.GetItemRequest_builder{Id: created.GetItem().GetId()}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVaultHandler_DeleteItem_NotFound(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	_, err := h.DeleteItem(ctx, vaultpb.DeleteItemRequest_builder{Id: "ghost"}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestVaultHandler_ListItems_Empty(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	resp, err := h.ListItems(ctx, vaultpb.ListItemsRequest_builder{}.Build())
	require.NoError(t, err)
	assert.Empty(t, resp.GetItems())
}

func TestVaultHandler_ListItems_Multiple(t *testing.T) {
	h, _ := newVaultHandler()
	ctx := ctxWithUser("user-alice")

	for i := 0; i < 3; i++ {
		_, err := h.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
			Type:    commonpb.ItemType_TEXT,
			Payload: []byte("data"),
		}.Build())
		require.NoError(t, err)
	}
	// create item for another user — must not appear
	_, err := h.CreateItem(ctxWithUser("user-bob"), vaultpb.CreateItemRequest_builder{Payload: []byte("bob")}.Build())
	require.NoError(t, err)

	resp, err := h.ListItems(ctx, vaultpb.ListItemsRequest_builder{}.Build())
	require.NoError(t, err)
	assert.Len(t, resp.GetItems(), 3)
}

func TestVaultHandler_ListItems_Unauthenticated(t *testing.T) {
	h, _ := newVaultHandler()
	_, err := h.ListItems(context.Background(), vaultpb.ListItemsRequest_builder{}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}
