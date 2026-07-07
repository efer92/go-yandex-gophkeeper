package audit_test

import (
	"testing"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/audit"
	"github.com/stretchr/testify/assert"
)

func TestNew_SetsFields(t *testing.T) {
	before := time.Now()
	evt := audit.New("user-42", audit.ActionLogin, audit.ResultOK)
	after := time.Now()

	assert.Equal(t, "user-42", evt.UserID)
	assert.Equal(t, audit.ActionLogin, evt.Action)
	assert.Equal(t, audit.ResultOK, evt.Result)
	assert.True(t, !evt.CreatedAt.Before(before) && !evt.CreatedAt.After(after),
		"CreatedAt should be between before and after")
}

func TestNew_FailedLogin(t *testing.T) {
	evt := audit.New("user-1", audit.ActionLoginFailed, audit.ResultDenied)
	assert.Equal(t, audit.ActionLoginFailed, evt.Action)
	assert.Equal(t, audit.ResultDenied, evt.Result)
}

func TestNew_VaultActions(t *testing.T) {
	actions := []audit.Action{
		audit.ActionVaultCreate,
		audit.ActionVaultRead,
		audit.ActionVaultUpdate,
		audit.ActionVaultDelete,
		audit.ActionVaultList,
	}
	for _, a := range actions {
		evt := audit.New("u", a, audit.ResultOK)
		assert.Equal(t, a, evt.Action)
	}
}

func TestNew_MFAActions(t *testing.T) {
	evt := audit.New("u", audit.ActionMFAEnroll, audit.ResultOK)
	assert.Equal(t, audit.ActionMFAEnroll, evt.Action)

	evt2 := audit.New("u", audit.ActionMFAFailed, audit.ResultDenied)
	assert.Equal(t, audit.ResultDenied, evt2.Result)
}
