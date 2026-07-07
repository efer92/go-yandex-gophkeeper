package handler

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	syncpb "github.com/efer92/go-yandex-gophkeeper/gen/sync"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
)

// SyncHandler implements syncpb.SyncServiceServer.
type SyncHandler struct {
	syncpb.UnimplementedSyncServiceServer
	syncSvc  *service.SyncService
	vaultSvc *service.VaultService
}

// NewSyncHandler creates a SyncHandler.
func NewSyncHandler(syncSvc *service.SyncService, vaultSvc *service.VaultService) *SyncHandler {
	return &SyncHandler{syncSvc: syncSvc, vaultSvc: vaultSvc}
}

// Subscribe sends the client all items it's missing, then streams live updates.
func (h *SyncHandler) Subscribe(req *syncpb.SubscribeRequest, stream syncpb.SyncService_SubscribeServer) error {
	ctx := stream.Context()
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}

	// Build a set of known versions from the client.
	knownVersions := make(map[string]int64, len(req.GetKnownVersions()))
	for _, kv := range req.GetKnownVersions() {
		knownVersions[kv.GetItemId()] = kv.GetVersion()
	}

	// Fetch all server items and send any that are newer than what the client has.
	items, _, err := h.vaultSvc.List(ctx, userID, storage.ListFilter{Limit: 1000})
	if err != nil {
		return status.Error(codes.Internal, "list items failed")
	}
	for _, item := range items {
		clientVer, known := knownVersions[item.ID]
		if !known || item.Version > clientVer {
			evt := syncpb.SyncEvent_builder{
				Type: syncpb.SyncEvent_UPSERT,
				Item: storageItemToProto(item),
			}.Build()
			if err := stream.Send(evt); err != nil {
				return err
			}
		}
	}

	// Subscribe to live events.
	ch, cancel := h.syncSvc.Subscribe(userID)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-ch:
			if !ok {
				return nil
			}
			pbEvt := &syncpb.SyncEvent{}
			switch evt.Type {
			case "upsert":
				pbEvt.SetType(syncpb.SyncEvent_UPSERT)
				pbEvt.SetItem(storageItemToProto(*evt.Item))
			case "delete":
				pbEvt.SetType(syncpb.SyncEvent_DELETE)
				pbEvt.SetDeletedId(evt.DeletedID)
			}
			if err := stream.Send(pbEvt); err != nil {
				return err
			}
		}
	}
}

func storageItemToProto(item storage.VaultItem) *commonpb.VaultItem {
	return commonpb.VaultItem_builder{
		Id:        item.ID,
		UserId:    item.UserID,
		Payload:   item.Payload,
		Metadata:  item.Metadata,
		Version:   item.Version,
		CreatedAt: timestamppb.New(item.CreatedAt),
		UpdatedAt: timestamppb.New(item.UpdatedAt),
	}.Build()
}
