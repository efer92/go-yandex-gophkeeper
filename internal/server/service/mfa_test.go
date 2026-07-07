package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
)

func newMFASvc(t *testing.T) (*service.MFAService, *mockStore) {
	t.Helper()
	store := newMockStore()
	jwtMgr := newTestJWT()
	return service.NewMFAService(store, jwtMgr, "GophKeeper"), store
}

func TestMFAService_EnrollTOTP_Success(t *testing.T) {
	svc, _ := newMFASvc(t)

	result, err := svc.EnrollTOTP(context.Background(), "user-alice", "alice@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, result.TOTPID)
	assert.NotEmpty(t, result.Secret)
	assert.Contains(t, result.OTPAuthURL, "otpauth://")
}

func TestMFAService_ConfirmTOTP_Success(t *testing.T) {
	svc, store := newMFASvc(t)

	// First create a user so SetMFARequired works
	_, _ = store.users.Create(context.Background(), storageUser("alice"))

	enrolled, err := svc.EnrollTOTP(context.Background(), "user-alice", "alice")
	require.NoError(t, err)

	code, err := totp.GenerateCodeCustom(enrolled.Secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	err = svc.ConfirmTOTP(context.Background(), "user-alice", enrolled.TOTPID, code)
	require.NoError(t, err)
}

func TestMFAService_ConfirmTOTP_WrongCode(t *testing.T) {
	svc, store := newMFASvc(t)
	_, _ = store.users.Create(context.Background(), storageUser("alice"))

	enrolled, _ := svc.EnrollTOTP(context.Background(), "user-alice", "alice")
	err := svc.ConfirmTOTP(context.Background(), "user-alice", enrolled.TOTPID, "000000")
	assert.ErrorIs(t, err, service.ErrMFAInvalid)
}

func TestMFAService_ConfirmTOTP_InvalidTOTPID(t *testing.T) {
	svc, _ := newMFASvc(t)
	err := svc.ConfirmTOTP(context.Background(), "user-alice", "bad-id", "123456")
	assert.ErrorIs(t, err, service.ErrMFAInvalid)
}

func TestMFAService_VerifyTOTP_Success(t *testing.T) {
	svc, store := newMFASvc(t)
	_, _ = store.users.Create(context.Background(), storageUser("alice"))

	enrolled, _ := svc.EnrollTOTP(context.Background(), "user-alice", "alice")

	code, _ := totp.GenerateCodeCustom(enrolled.Secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	_ = svc.ConfirmTOTP(context.Background(), "user-alice", enrolled.TOTPID, code)

	// Re-generate a fresh code for VerifyTOTP
	code2, _ := totp.GenerateCodeCustom(enrolled.Secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	result, err := svc.VerifyTOTP(context.Background(), service.VerifyMFAInput{
		UserID:    "user-alice",
		TOTPCode:  code2,
		SessionID: "sess-1",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

func TestMFAService_VerifyTOTP_WrongCode(t *testing.T) {
	svc, store := newMFASvc(t)
	_, _ = store.users.Create(context.Background(), storageUser("alice"))

	enrolled, _ := svc.EnrollTOTP(context.Background(), "user-alice", "alice")
	code, _ := totp.GenerateCodeCustom(enrolled.Secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	_ = svc.ConfirmTOTP(context.Background(), "user-alice", enrolled.TOTPID, code)

	_, err := svc.VerifyTOTP(context.Background(), service.VerifyMFAInput{
		UserID:   "user-alice",
		TOTPCode: "000000",
	})
	assert.ErrorIs(t, err, service.ErrMFAInvalid)
}

func TestMFAService_VerifyTOTP_NoConfirmedTOTP(t *testing.T) {
	svc, _ := newMFASvc(t)
	_, err := svc.VerifyTOTP(context.Background(), service.VerifyMFAInput{
		UserID:   "user-nobody",
		TOTPCode: "123456",
	})
	assert.ErrorIs(t, err, service.ErrMFAInvalid)
}

// storageUser builds a minimal storage.User for the mock.
func storageUser(username string) storage.User {
	return storage.User{Username: username}
}
