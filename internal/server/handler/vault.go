package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
)

// VaultHandler implements vaultpb.VaultServiceServer.
type VaultHandler struct {
	vaultpb.UnimplementedVaultServiceServer
	vaultSvc *service.VaultService
}

// NewVaultHandler creates a VaultHandler.
func NewVaultHandler(vaultSvc *service.VaultService) *VaultHandler {
	return &VaultHandler{vaultSvc: vaultSvc}
}

// CreateItem stores a new encrypted vault item owned by the authenticated user.
func (h *VaultHandler) CreateItem(ctx context.Context, req *vaultpb.CreateItemRequest) (*vaultpb.CreateItemResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	item, err := h.vaultSvc.Create(ctx, userID, itemTypeName(req.GetType()), req.GetPayload(), req.GetMetadata())
	if err != nil {
		return nil, status.Error(codes.Internal, "create item failed")
	}
	return vaultpb.CreateItemResponse_builder{Item: toProtoItem(item)}.Build(), nil
}

// GetItem returns a single vault item by ID, scoped to the authenticated user.
func (h *VaultHandler) GetItem(ctx context.Context, req *vaultpb.GetItemRequest) (*vaultpb.GetItemResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	item, err := h.vaultSvc.Get(ctx, req.GetId(), userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "item not found")
		}
		return nil, status.Error(codes.Internal, "get item failed")
	}
	return vaultpb.GetItemResponse_builder{Item: toProtoItem(item)}.Build(), nil
}

// UpdateItem replaces the payload and metadata of an existing vault item.
func (h *VaultHandler) UpdateItem(ctx context.Context, req *vaultpb.UpdateItemRequest) (*vaultpb.UpdateItemResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	item, err := h.vaultSvc.Update(ctx, req.GetId(), userID, req.GetPayload(), req.GetMetadata())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "item not found")
		}
		return nil, status.Error(codes.Internal, "update item failed")
	}
	return vaultpb.UpdateItemResponse_builder{Item: toProtoItem(item)}.Build(), nil
}

// DeleteItem removes a vault item owned by the authenticated user.
func (h *VaultHandler) DeleteItem(ctx context.Context, req *vaultpb.DeleteItemRequest) (*vaultpb.DeleteItemResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if err := h.vaultSvc.Delete(ctx, req.GetId(), userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "item not found")
		}
		return nil, status.Error(codes.Internal, "delete item failed")
	}
	return vaultpb.DeleteItemResponse_builder{}.Build(), nil
}

// ListItems returns a paginated list of vault items, optionally filtered by type.
func (h *VaultHandler) ListItems(ctx context.Context, req *vaultpb.ListItemsRequest) (*vaultpb.ListItemsResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	items, cursor, err := h.vaultSvc.List(ctx, userID, storage.ListFilter{
		TypeFilter: itemTypeName(req.GetTypeFilter()),
		Limit:      int(req.GetLimit()),
		Cursor:     req.GetCursor(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "list items failed")
	}
	pbItems := make([]*commonpb.VaultItem, len(items))
	for i, item := range items {
		pbItems[i] = toProtoItem(item)
	}
	return vaultpb.ListItemsResponse_builder{Items: pbItems, NextCursor: cursor}.Build(), nil
}

func toProtoItem(item storage.VaultItem) *commonpb.VaultItem {
	return commonpb.VaultItem_builder{
		Id:        item.ID,
		UserId:    item.UserID,
		Type:      toProtoItemType(item.Type),
		Payload:   item.Payload,
		Metadata:  item.Metadata,
		Version:   item.Version,
		CreatedAt: timestamppb.New(item.CreatedAt),
		UpdatedAt: timestamppb.New(item.UpdatedAt),
	}.Build()
}

func itemTypeName(t commonpb.ItemType) string {
	switch t {
	case commonpb.ItemType_CREDENTIAL:
		return "credential"
	case commonpb.ItemType_TEXT:
		return "text"
	case commonpb.ItemType_BINARY:
		return "binary"
	case commonpb.ItemType_CARD:
		return "card"
	case commonpb.ItemType_OTP:
		return "otp"
	default:
		return ""
	}
}

func toProtoItemType(s string) commonpb.ItemType {
	switch s {
	case "credential":
		return commonpb.ItemType_CREDENTIAL
	case "text":
		return commonpb.ItemType_TEXT
	case "binary":
		return commonpb.ItemType_BINARY
	case "card":
		return commonpb.ItemType_CARD
	case "otp":
		return commonpb.ItemType_OTP
	default:
		return commonpb.ItemType_ITEM_TYPE_UNSPECIFIED
	}
}
