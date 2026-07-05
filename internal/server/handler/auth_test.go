package handler_test

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/handler"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

func newAuthHandler() (*handler.AuthHandler, *testutil.MockStore) {
	store := testutil.NewMockStore()
	jwtMgr := testutil.NewTestJWT()
	authSvc := service.NewAuthService(store, jwtMgr)
	mfaSvc := service.NewMFAService(store, jwtMgr, "GophKeeper")
	return handler.NewAuthHandler(authSvc, mfaSvc), store
}

func registerUser(t *testing.T, h *handler.AuthHandler, username, password string) *authpb.RegisterResponse {
	t.Helper()
	kdfParams := crypto.DefaultKDFParams()
	masterKey := crypto.DeriveKey([]byte(password), kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)
	vaultKey, _ := crypto.GenerateVaultSymKey()
	sealedKey, _ := crypto.SealVaultSymKey(vaultKey, encKey)
	kdfJSON, _ := crypto.MarshalKDFParams(kdfParams)

	resp, err := h.Register(context.Background(), &authpb.RegisterRequest{
		Username:      username,
		Email:         username + "@example.com",
		Password:      password,
		VaultSymKey:   sealedKey,
		KdfParamsJson: kdfJSON,
	})
	require.NoError(t, err)
	return resp
}

func TestAuthHandler_Register_Success(t *testing.T) {
	h, _ := newAuthHandler()
	resp := registerUser(t, h, "alice", "secret123")
	assert.NotEmpty(t, resp.UserId)
}

func TestAuthHandler_Register_DuplicateUser(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	_, err := h.Register(context.Background(), &authpb.RegisterRequest{
		Username: "alice", Email: "other@example.com",
		Password: "other", VaultSymKey: []byte("k"), KdfParamsJson: "{}",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestAuthHandler_Login_Success(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	resp, err := h.Login(context.Background(), &authpb.LoginRequest{
		Username: "alice", Password: "secret123",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestAuthHandler_Login_WrongPassword(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	_, err := h.Login(context.Background(), &authpb.LoginRequest{
		Username: "alice", Password: "wrong",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_Login_UnknownUser(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.Login(context.Background(), &authpb.LoginRequest{
		Username: "ghost", Password: "pass",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_Refresh_Valid(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	loginResp, _ := h.Login(context.Background(), &authpb.LoginRequest{
		Username: "alice", Password: "secret123",
	})

	resp, err := h.Refresh(context.Background(), &authpb.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestAuthHandler_Refresh_Invalid(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.Refresh(context.Background(), &authpb.RefreshRequest{
		RefreshToken: "bad-token",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_Logout_Success(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	loginResp, _ := h.Login(context.Background(), &authpb.LoginRequest{
		Username: "alice", Password: "secret123",
	})

	_, err := h.Logout(context.Background(), &authpb.LogoutRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	require.NoError(t, err)

	// Refresh after logout must fail
	_, err = h.Refresh(context.Background(), &authpb.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	assert.Error(t, err)
}

func TestAuthHandler_EnrollTOTP_RequiresAuth(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.EnrollTOTP(context.Background(), &authpb.EnrollTOTPRequest{Label: "test"})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_EnrollTOTP_Success(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	ctx := ctxWithUser("user-alice")
	resp, err := h.EnrollTOTP(ctx, &authpb.EnrollTOTPRequest{Label: "alice@GophKeeper"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.TotpId)
	assert.NotEmpty(t, resp.Secret)
	assert.NotEmpty(t, resp.OtpauthUrl)
}

func TestAuthHandler_ConfirmTOTP_RequiresAuth(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.ConfirmTOTP(context.Background(), &authpb.ConfirmTOTPRequest{
		TotpId: "tid", Code: "123456",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_VerifyMFA_RequiresAuth(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.VerifyMFA(context.Background(), &authpb.VerifyMFARequest{
		SessionId: "sid", TotpCode: "123456",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_ConfirmTOTP_InvalidCode(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, err := h.EnrollTOTP(ctx, &authpb.EnrollTOTPRequest{Label: "alice"})
	require.NoError(t, err)

	resp, err := h.ConfirmTOTP(ctx, &authpb.ConfirmTOTPRequest{
		TotpId: enroll.TotpId, Code: "000000",
	})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
}

func TestAuthHandler_ConfirmTOTP_Success(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, err := h.EnrollTOTP(ctx, &authpb.EnrollTOTPRequest{Label: "alice"})
	require.NoError(t, err)

	code, err := totp.GenerateCode(enroll.Secret, time.Now())
	require.NoError(t, err)

	resp, err := h.ConfirmTOTP(ctx, &authpb.ConfirmTOTPRequest{
		TotpId: enroll.TotpId, Code: code,
	})
	require.NoError(t, err)
	assert.True(t, resp.Ok)
}

func TestAuthHandler_VerifyMFA_InvalidCode(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, _ := h.EnrollTOTP(ctx, &authpb.EnrollTOTPRequest{Label: "alice"})
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	_, _ = h.ConfirmTOTP(ctx, &authpb.ConfirmTOTPRequest{TotpId: enroll.TotpId, Code: code})

	_, err := h.VerifyMFA(ctx, &authpb.VerifyMFARequest{
		SessionId: "sid", TotpCode: "000000",
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_VerifyMFA_Success(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, _ := h.EnrollTOTP(ctx, &authpb.EnrollTOTPRequest{Label: "alice"})
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	confirm, err := h.ConfirmTOTP(ctx, &authpb.ConfirmTOTPRequest{TotpId: enroll.TotpId, Code: code})
	require.NoError(t, err)
	require.True(t, confirm.Ok)

	verifyCode, _ := totp.GenerateCode(enroll.Secret, time.Now())
	resp, err := h.VerifyMFA(ctx, &authpb.VerifyMFARequest{
		SessionId: "sid", TotpCode: verifyCode,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}
