// Package handler implements gRPC service handlers for GophKeeper.
package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
)

// AuthHandler implements authpb.AuthServiceServer.
type AuthHandler struct {
	authpb.UnimplementedAuthServiceServer
	authSvc *service.AuthService
	mfaSvc  *service.MFAService
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(authSvc *service.AuthService, mfaSvc *service.MFAService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, mfaSvc: mfaSvc}
}

// Register creates a new user account.
func (h *AuthHandler) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	result, err := h.authSvc.Register(ctx, service.RegisterInput{
		Username:      req.GetUsername(),
		Email:         req.GetEmail(),
		Password:      req.GetPassword(),
		VaultSymKey:   req.GetVaultSymKey(),
		KDFParamsJSON: req.GetKdfParamsJson(),
	})
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "registration failed")
	}
	return authpb.RegisterResponse_builder{UserId: result.UserID}.Build(), nil
}

// Login authenticates a user and returns tokens.
func (h *AuthHandler) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	result, err := h.authSvc.Login(ctx, service.LoginInput{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "login failed")
	}
	return authpb.LoginResponse_builder{
		AccessToken:   result.AccessToken,
		RefreshToken:  result.RefreshToken,
		NeedsMfa:      result.NeedsMFA,
		SessionId:     result.SessionID,
		KdfParamsJson: result.KDFParamsJSON,
		VaultSymKey:   result.VaultSymKey,
	}.Build(), nil
}

// Refresh exchanges a valid refresh token for a new access token.
func (h *AuthHandler) Refresh(ctx context.Context, req *authpb.RefreshRequest) (*authpb.RefreshResponse, error) {
	token, err := h.authSvc.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}
	return authpb.RefreshResponse_builder{AccessToken: token}.Build(), nil
}

// Logout invalidates the provided refresh token.
func (h *AuthHandler) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	_ = h.authSvc.Logout(ctx, userID, req.GetRefreshToken())
	return authpb.LogoutResponse_builder{}.Build(), nil
}

// EnrollTOTP generates a new TOTP secret and returns the otpauth URL for QR display.
func (h *AuthHandler) EnrollTOTP(ctx context.Context, req *authpb.EnrollTOTPRequest) (*authpb.EnrollTOTPResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	result, err := h.mfaSvc.EnrollTOTP(ctx, userID, req.GetLabel())
	if err != nil {
		return nil, status.Error(codes.Internal, "enroll totp failed")
	}
	return authpb.EnrollTOTPResponse_builder{
		TotpId:     result.TOTPID,
		Secret:     result.Secret,
		OtpauthUrl: result.OTPAuthURL,
	}.Build(), nil
}

// ConfirmTOTP verifies the first TOTP code and activates MFA for the user.
func (h *AuthHandler) ConfirmTOTP(ctx context.Context, req *authpb.ConfirmTOTPRequest) (*authpb.ConfirmTOTPResponse, error) {
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if err := h.mfaSvc.ConfirmTOTP(ctx, userID, req.GetTotpId(), req.GetCode()); err != nil {
		return authpb.ConfirmTOTPResponse_builder{Ok: false}.Build(), nil
	}
	return authpb.ConfirmTOTPResponse_builder{Ok: true}.Build(), nil
}

// VerifyMFA validates a TOTP code for an in-progress MFA session and issues tokens.
func (h *AuthHandler) VerifyMFA(ctx context.Context, req *authpb.VerifyMFARequest) (*authpb.VerifyMFAResponse, error) {
	// userID is set in context by the auth middleware after the client provides it via metadata.
	userID, ok := userIDFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	result, err := h.mfaSvc.VerifyTOTP(ctx, service.VerifyMFAInput{
		SessionID: req.GetSessionId(),
		TOTPCode:  req.GetTotpCode(),
		UserID:    userID,
	})
	if err != nil {
		if errors.Is(err, service.ErrMFAInvalid) {
			return nil, status.Error(codes.Unauthenticated, "invalid MFA code")
		}
		return nil, status.Error(codes.Internal, "mfa verification failed")
	}
	return authpb.VerifyMFAResponse_builder{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
	}.Build(), nil
}
