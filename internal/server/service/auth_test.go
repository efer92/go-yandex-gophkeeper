package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestJWT() *jwtpkg.Manager {
	return jwtpkg.NewManager(jwtpkg.Config{
		Secret:          []byte("test-secret-padded-to-32-bytes!!"),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	})
}

func registerAlice(t *testing.T, svc *service.AuthService) service.RegisterResult {
	t.Helper()
	kdfParams, err := crypto.DefaultKDFParams()
	require.NoError(t, err)
	masterKey := crypto.DeriveKey([]byte("alice-password"), kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)
	vaultKey, _ := crypto.GenerateVaultSymKey()
	sealedKey, _ := crypto.SealVaultSymKey(vaultKey, encKey)
	kdfJSON, _ := crypto.MarshalKDFParams(kdfParams)

	result, err := svc.Register(context.Background(), service.RegisterInput{
		Username:      "alice",
		Email:         "alice@example.com",
		Password:      "alice-password",
		VaultSymKey:   sealedKey,
		KDFParamsJSON: kdfJSON,
	})
	require.NoError(t, err)
	return result
}

func TestAuthService_Register_Success(t *testing.T) {
	store := newMockStore()
	svc := service.NewAuthService(store, newTestJWT())
	result := registerAlice(t, svc)
	assert.NotEmpty(t, result.UserID)
}

func TestAuthService_Register_DuplicateUsername(t *testing.T) {
	store := newMockStore()
	svc := service.NewAuthService(store, newTestJWT())
	registerAlice(t, svc)

	_, err := svc.Register(context.Background(), service.RegisterInput{
		Username: "alice", Email: "other@example.com", Password: "p",
		VaultSymKey: []byte("k"), KDFParamsJSON: "{}",
	})
	assert.ErrorIs(t, err, service.ErrUserExists)
}

func TestAuthService_Login_Success(t *testing.T) {
	store := newMockStore()
	jwtMgr := newTestJWT()
	svc := service.NewAuthService(store, jwtMgr)
	registerAlice(t, svc)

	result, err := svc.Login(context.Background(), service.LoginInput{
		Username: "alice", Password: "alice-password",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.False(t, result.NeedsMFA)

	// Access token must be valid.
	claims, err := jwtMgr.ParseAccessToken(result.AccessToken)
	require.NoError(t, err)
	assert.Contains(t, claims.Subject, "alice")
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	store := newMockStore()
	svc := service.NewAuthService(store, newTestJWT())
	registerAlice(t, svc)

	_, err := svc.Login(context.Background(), service.LoginInput{Username: "alice", Password: "wrong"})
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

func TestAuthService_Login_UnknownUser(t *testing.T) {
	store := newMockStore()
	svc := service.NewAuthService(store, newTestJWT())

	_, err := svc.Login(context.Background(), service.LoginInput{Username: "ghost", Password: "x"})
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

func TestAuthService_Refresh_Valid(t *testing.T) {
	store := newMockStore()
	jwtMgr := newTestJWT()
	svc := service.NewAuthService(store, jwtMgr)
	registerAlice(t, svc)

	loginResult, err := svc.Login(context.Background(), service.LoginInput{Username: "alice", Password: "alice-password"})
	require.NoError(t, err)

	newToken, err := svc.Refresh(context.Background(), loginResult.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newToken)
}

func TestAuthService_Refresh_AfterLogout(t *testing.T) {
	store := newMockStore()
	svc := service.NewAuthService(store, newTestJWT())
	registerAlice(t, svc)

	loginResult, _ := svc.Login(context.Background(), service.LoginInput{Username: "alice", Password: "alice-password"})
	require.NoError(t, svc.Logout(context.Background(), "user-alice", loginResult.RefreshToken))

	_, err := svc.Refresh(context.Background(), loginResult.RefreshToken)
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

func TestVaultService_CRUD(t *testing.T) {
	store := newMockStore()
	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(store, syncSvc)
	ctx := context.Background()

	// Create
	item, err := vaultSvc.Create(ctx, "user-1", "credential", []byte("encrypted"), "GitHub")
	require.NoError(t, err)
	assert.NotEmpty(t, item.ID)

	// Get
	got, err := vaultSvc.Get(ctx, item.ID, "user-1")
	require.NoError(t, err)
	assert.Equal(t, item.ID, got.ID)

	// Cross-user ownership enforced
	_, err = vaultSvc.Get(ctx, item.ID, "other-user")
	assert.Error(t, err)

	// Update
	updated, err := vaultSvc.Update(ctx, item.ID, "user-1", []byte("new-encrypted"), "GitHub v2")
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)

	// List
	items, _, err := vaultSvc.List(ctx, "user-1", storage.ListFilter{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, items, 1)

	// Delete
	require.NoError(t, vaultSvc.Delete(ctx, item.ID, "user-1"))
	_, err = vaultSvc.Get(ctx, item.ID, "user-1")
	assert.Error(t, err)
}
