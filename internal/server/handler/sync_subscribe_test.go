package handler_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	syncpb "github.com/efer92/go-yandex-gophkeeper/gen/sync"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/handler"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

// fakeSubscribeStream implements syncpb.SyncService_SubscribeServer for tests.
type fakeSubscribeStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*syncpb.SyncEvent
}

func (s *fakeSubscribeStream) Context() context.Context { return s.ctx }
func (s *fakeSubscribeStream) Send(e *syncpb.SyncEvent) error {
	s.sent = append(s.sent, e)
	return nil
}
func (s *fakeSubscribeStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeSubscribeStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeSubscribeStream) SetTrailer(metadata.MD)       {}

func newSyncSetup() (*handler.SyncHandler, *handler.VaultHandler) {
	store := testutil.NewMockStore()
	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(store, syncSvc)
	return handler.NewSyncHandler(syncSvc, vaultSvc), handler.NewVaultHandler(vaultSvc)
}

func TestSyncHandler_Subscribe_Unauthenticated(t *testing.T) {
	h, _ := newSyncSetup()
	stream := &fakeSubscribeStream{ctx: context.Background()}
	err := h.Subscribe(syncpb.SubscribeRequest_builder{}.Build(), stream)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestSyncHandler_Subscribe_SendsMissingItems(t *testing.T) {
	h, vh := newSyncSetup()
	userCtx := ctxWithUser("user-alice")

	// Create two items for the user.
	c1, err := vh.CreateItem(userCtx, vaultpb.CreateItemRequest_builder{
		Type: commonpb.ItemType_CREDENTIAL, Payload: []byte("a"),
	}.Build())
	require.NoError(t, err)
	_, err = vh.CreateItem(userCtx, vaultpb.CreateItemRequest_builder{
		Type: commonpb.ItemType_CREDENTIAL, Payload: []byte("b"),
	}.Build())
	require.NoError(t, err)

	// Stream context is cancelled shortly so the live loop exits.
	ctx, cancel := context.WithCancel(ctxWithUser("user-alice"))
	stream := &fakeSubscribeStream{ctx: ctx}

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// Client already knows c1 at its current version, so only the second item
	// should be streamed during the initial catch-up.
	err = h.Subscribe(syncpb.SubscribeRequest_builder{
		KnownVersions: []*syncpb.ItemVersion{
			syncpb.ItemVersion_builder{ItemId: c1.GetItem().GetId(), Version: c1.GetItem().GetVersion()}.Build(),
		},
	}.Build(), stream)
	require.NoError(t, err)

	assert.Len(t, stream.sent, 1)
	assert.Equal(t, syncpb.SyncEvent_UPSERT, stream.sent[0].GetType())
	assert.Equal(t, []byte("b"), stream.sent[0].GetItem().GetPayload())
}

func TestSyncHandler_Subscribe_LiveUpsert(t *testing.T) {
	store := testutil.NewMockStore()
	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(store, syncSvc)
	h := handler.NewSyncHandler(syncSvc, vaultSvc)
	vh := handler.NewVaultHandler(vaultSvc)

	ctx, cancel := context.WithCancel(ctxWithUser("user-alice"))
	defer cancel()
	stream := &fakeSubscribeStream{ctx: ctx}

	done := make(chan error, 1)
	go func() {
		done <- h.Subscribe(syncpb.SubscribeRequest_builder{}.Build(), stream)
	}()

	// Give Subscribe time to register its live subscription.
	time.Sleep(50 * time.Millisecond)
	_, err := vh.CreateItem(ctxWithUser("user-alice"), vaultpb.CreateItemRequest_builder{
		Type: commonpb.ItemType_TEXT, Payload: []byte("live"),
	}.Build())
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	cancel()
	require.NoError(t, <-done)

	require.NotEmpty(t, stream.sent)
	assert.Equal(t, syncpb.SyncEvent_UPSERT, stream.sent[len(stream.sent)-1].GetType())
}
