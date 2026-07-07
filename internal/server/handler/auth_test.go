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
	kdfParams, err := crypto.DefaultKDFParams()
	require.NoError(t, err)
	masterKey := crypto.DeriveKey([]byte(password), kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)
	vaultKey, _ := crypto.GenerateVaultSymKey()
	sealedKey, _ := crypto.SealVaultSymKey(vaultKey, encKey)
	kdfJSON, _ := crypto.MarshalKDFParams(kdfParams)

	resp, err := h.Register(context.Background(), authpb.RegisterRequest_builder{
		Username:      username,
		Email:         username + "@example.com",
		Password:      password,
		VaultSymKey:   sealedKey,
		KdfParamsJson: kdfJSON,
	}.Build())
	require.NoError(t, err)
	return resp
}

func TestAuthHandler_Register_Success(t *testing.T) {
	h, _ := newAuthHandler()
	resp := registerUser(t, h, "alice", "secret123")
	assert.NotEmpty(t, resp.GetUserId())
}

func TestAuthHandler_Register_DuplicateUser(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	_, err := h.Register(context.Background(), authpb.RegisterRequest_builder{
		Username: "alice", Email: "other@example.com",
		Password: "other", VaultSymKey: []byte("k"), KdfParamsJson: "{}",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestAuthHandler_Login_Success(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	resp, err := h.Login(context.Background(), authpb.LoginRequest_builder{
		Username: "alice", Password: "secret123",
	}.Build())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetAccessToken())
	assert.NotEmpty(t, resp.GetRefreshToken())
}

func TestAuthHandler_Login_WrongPassword(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	_, err := h.Login(context.Background(), authpb.LoginRequest_builder{
		Username: "alice", Password: "wrong",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_Login_UnknownUser(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.Login(context.Background(), authpb.LoginRequest_builder{
		Username: "ghost", Password: "pass",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_Refresh_Valid(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	loginResp, _ := h.Login(context.Background(), authpb.LoginRequest_builder{
		Username: "alice", Password: "secret123",
	}.Build())

	resp, err := h.Refresh(context.Background(), authpb.RefreshRequest_builder{
		RefreshToken: loginResp.GetRefreshToken(),
	}.Build())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetAccessToken())
}

func TestAuthHandler_Refresh_Invalid(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.Refresh(context.Background(), authpb.RefreshRequest_builder{
		RefreshToken: "bad-token",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_Logout_Success(t *testing.T) {
	h, _ := newAuthHandler()
	regResp := registerUser(t, h, "alice", "secret123")

	loginResp, _ := h.Login(context.Background(), authpb.LoginRequest_builder{
		Username: "alice", Password: "secret123",
	}.Build())

	_, err := h.Logout(ctxWithUser(regResp.GetUserId()), authpb.LogoutRequest_builder{
		RefreshToken: loginResp.GetRefreshToken(),
	}.Build())
	require.NoError(t, err)

	// Refresh after logout must fail
	_, err = h.Refresh(context.Background(), authpb.RefreshRequest_builder{
		RefreshToken: loginResp.GetRefreshToken(),
	}.Build())
	assert.Error(t, err)
}

func TestAuthHandler_EnrollTOTP_RequiresAuth(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.EnrollTOTP(context.Background(), authpb.EnrollTOTPRequest_builder{Label: "test"}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_EnrollTOTP_Success(t *testing.T) {
	h, _ := newAuthHandler()
	registerUser(t, h, "alice", "secret123")

	ctx := ctxWithUser("user-alice")
	resp, err := h.EnrollTOTP(ctx, authpb.EnrollTOTPRequest_builder{Label: "alice@GophKeeper"}.Build())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetTotpId())
	assert.NotEmpty(t, resp.GetSecret())
	assert.NotEmpty(t, resp.GetOtpauthUrl())
}

func TestAuthHandler_ConfirmTOTP_RequiresAuth(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.ConfirmTOTP(context.Background(), authpb.ConfirmTOTPRequest_builder{
		TotpId: "tid", Code: "123456",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_VerifyMFA_RequiresAuth(t *testing.T) {
	h, _ := newAuthHandler()
	_, err := h.VerifyMFA(context.Background(), authpb.VerifyMFARequest_builder{
		SessionId: "sid", TotpCode: "123456",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_ConfirmTOTP_InvalidCode(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, err := h.EnrollTOTP(ctx, authpb.EnrollTOTPRequest_builder{Label: "alice"}.Build())
	require.NoError(t, err)

	resp, err := h.ConfirmTOTP(ctx, authpb.ConfirmTOTPRequest_builder{
		TotpId: enroll.GetTotpId(), Code: "000000",
	}.Build())
	require.NoError(t, err)
	assert.False(t, resp.GetOk())
}

func TestAuthHandler_ConfirmTOTP_Success(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, err := h.EnrollTOTP(ctx, authpb.EnrollTOTPRequest_builder{Label: "alice"}.Build())
	require.NoError(t, err)

	code, err := totp.GenerateCode(enroll.GetSecret(), time.Now())
	require.NoError(t, err)

	resp, err := h.ConfirmTOTP(ctx, authpb.ConfirmTOTPRequest_builder{
		TotpId: enroll.GetTotpId(), Code: code,
	}.Build())
	require.NoError(t, err)
	assert.True(t, resp.GetOk())
}

func TestAuthHandler_VerifyMFA_InvalidCode(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, _ := h.EnrollTOTP(ctx, authpb.EnrollTOTPRequest_builder{Label: "alice"}.Build())
	code, _ := totp.GenerateCode(enroll.GetSecret(), time.Now())
	_, _ = h.ConfirmTOTP(ctx, authpb.ConfirmTOTPRequest_builder{TotpId: enroll.GetTotpId(), Code: code}.Build())

	_, err := h.VerifyMFA(ctx, authpb.VerifyMFARequest_builder{
		SessionId: "sid", TotpCode: "000000",
	}.Build())
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuthHandler_VerifyMFA_Success(t *testing.T) {
	h, _ := newAuthHandler()
	ctx := ctxWithUser("user-alice")
	enroll, _ := h.EnrollTOTP(ctx, authpb.EnrollTOTPRequest_builder{Label: "alice"}.Build())
	code, _ := totp.GenerateCode(enroll.GetSecret(), time.Now())
	confirm, err := h.ConfirmTOTP(ctx, authpb.ConfirmTOTPRequest_builder{TotpId: enroll.GetTotpId(), Code: code}.Build())
	require.NoError(t, err)
	require.True(t, confirm.GetOk())

	verifyCode, _ := totp.GenerateCode(enroll.GetSecret(), time.Now())
	resp, err := h.VerifyMFA(ctx, authpb.VerifyMFARequest_builder{
		SessionId: "sid", TotpCode: verifyCode,
	}.Build())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetAccessToken())
	assert.NotEmpty(t, resp.GetRefreshToken())
}
