//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	pgstore "github.com/efer92/go-yandex-gophkeeper/internal/server/storage/postgres"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
)

func TestVaultCRUD(t *testing.T) {
	dsn := startPostgres(t)
	require.NoError(t, pgstore.Migrate(dsn))

	ctx := context.Background()
	db, err := pgstore.New(ctx, dsn)
	require.NoError(t, err)
	defer db.Close()

	// Create a user
	kdfParams := crypto.DefaultKDFParams()
	masterKey := crypto.DeriveKey([]byte("pass"), kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)
	vaultKey, _ := crypto.GenerateVaultSymKey()
	sealedKey, _ := crypto.SealVaultSymKey(vaultKey, encKey)
	kdfJSON, _ := crypto.MarshalKDFParams(kdfParams)

	jwtMgr := jwtpkg.NewManager(jwtpkg.DefaultConfig([]byte("integration-test-secret-32bytes!")))
	authSvc := service.NewAuthService(db, jwtMgr)
	regResult, err := authSvc.Register(ctx, service.RegisterInput{
		Username: "bob", Email: "bob@example.com", Password: "pass",
		VaultSymKey: sealedKey, KDFParamsJSON: kdfJSON,
	})
	require.NoError(t, err)
	userID := regResult.UserID

	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(db, syncSvc)

	// Encrypt a payload with the vault symmetric key
	payload, err := crypto.Encrypt(vaultKey, []byte(`{"login":"bob@example.com","password":"secret123"}`))
	require.NoError(t, err)

	// Create
	item, err := vaultSvc.Create(ctx, userID, "credential", payload, "GitHub")
	require.NoError(t, err)
	assert.NotEmpty(t, item.ID)
	assert.Equal(t, int64(1), item.Version)

	// Get
	got, err := vaultSvc.Get(ctx, item.ID, userID)
	require.NoError(t, err)
	assert.Equal(t, item.ID, got.ID)

	// Decrypt and verify payload
	decrypted, err := crypto.Decrypt(vaultKey, got.Payload)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), "bob@example.com")

	// Update
	newPayload, _ := crypto.Encrypt(vaultKey, []byte(`{"login":"bob2@example.com","password":"newpass"}`))
	updated, err := vaultSvc.Update(ctx, item.ID, userID, newPayload, "GitHub Updated")
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)

	// List
	items, _, err := vaultSvc.List(ctx, userID, storage.ListFilter{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, items, 1)

	// Cross-user access denied
	_, err = vaultSvc.Get(ctx, item.ID, "other-user-id")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Delete
	require.NoError(t, vaultSvc.Delete(ctx, item.ID, userID))
	_, err = vaultSvc.Get(ctx, item.ID, userID)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}
