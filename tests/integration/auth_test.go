//go:build integration

// Package integration tests the full GophKeeper stack against a real PostgreSQL instance.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	pgstore "github.com/efer92/go-yandex-gophkeeper/internal/server/storage/postgres"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
)

func startPostgres(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("gophkeeper"),
		postgres.WithUsername("gophkeeper"),
		postgres.WithPassword("gophkeeper"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn
}

func TestAuthFlow(t *testing.T) {
	dsn := startPostgres(t)
	require.NoError(t, pgstore.Migrate(dsn))

	ctx := context.Background()
	db, err := pgstore.New(ctx, dsn)
	require.NoError(t, err)
	defer db.Close()

	jwtMgr := jwtpkg.NewManager(jwtpkg.DefaultConfig([]byte("integration-test-secret-32bytes!")))
	authSvc := service.NewAuthService(db, jwtMgr)

	// Generate vault key material
	kdfParams, err := crypto.DefaultKDFParams()
	require.NoError(t, err)
	masterKey := crypto.DeriveKey([]byte("strong-master-password"), kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)
	vaultKey, err := crypto.GenerateVaultSymKey()
	require.NoError(t, err)
	sealedKey, err := crypto.SealVaultSymKey(vaultKey, encKey)
	require.NoError(t, err)
	kdfJSON, err := crypto.MarshalKDFParams(kdfParams)
	require.NoError(t, err)

	// Register
	regResult, err := authSvc.Register(ctx, service.RegisterInput{
		Username:      "alice",
		Email:         "alice@example.com",
		Password:      "strong-master-password",
		VaultSymKey:   sealedKey,
		KDFParamsJSON: kdfJSON,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, regResult.UserID)

	// Duplicate registration should fail
	_, err = authSvc.Register(ctx, service.RegisterInput{
		Username:      "alice",
		Email:         "alice2@example.com",
		Password:      "pass",
		VaultSymKey:   sealedKey,
		KDFParamsJSON: kdfJSON,
	})
	assert.ErrorIs(t, err, service.ErrUserExists)

	// Login
	loginResult, err := authSvc.Login(ctx, service.LoginInput{
		Username: "alice",
		Password: "strong-master-password",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.NotEmpty(t, loginResult.RefreshToken)
	assert.False(t, loginResult.NeedsMFA)

	// Bad password
	_, err = authSvc.Login(ctx, service.LoginInput{Username: "alice", Password: "wrong"})
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)

	// Refresh
	newToken, err := authSvc.Refresh(ctx, loginResult.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newToken)

	// Validate new access token
	claims, err := jwtMgr.ParseAccessToken(newToken)
	require.NoError(t, err)
	assert.Equal(t, regResult.UserID, claims.Subject)

	// Logout
	require.NoError(t, authSvc.Logout(ctx, regResult.UserID, loginResult.RefreshToken))

	// Refresh after logout should fail
	_, err = authSvc.Refresh(ctx, loginResult.RefreshToken)
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}
