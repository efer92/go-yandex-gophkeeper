// Package audit provides structured audit event types for GophKeeper.
package audit

import "time"

// Action enumerates all auditable operations.
type Action string

const (
	ActionRegister    Action = "auth.register"
	ActionLogin       Action = "auth.login"
	ActionLoginFailed Action = "auth.login_failed"
	ActionLogout      Action = "auth.logout"
	ActionRefresh     Action = "auth.refresh"
	ActionMFAEnroll   Action = "mfa.enroll"
	ActionMFAVerify   Action = "mfa.verify"
	ActionMFAFailed   Action = "mfa.verify_failed"
	ActionVaultCreate Action = "vault.create"
	ActionVaultRead   Action = "vault.read"
	ActionVaultUpdate Action = "vault.update"
	ActionVaultDelete Action = "vault.delete"
	ActionVaultList   Action = "vault.list"
)

// Result enumerates possible audit outcomes.
type Result string

const (
	ResultOK     Result = "ok"
	ResultDenied Result = "denied"
)

// Event is a single audit log entry.
type Event struct {
	UserID    string
	Action    Action
	Result    Result
	IP        string
	UserAgent string
	Detail    map[string]any
	CreatedAt time.Time
}

// New creates a new Event with the current time.
func New(userID string, action Action, result Result) Event {
	return Event{
		UserID:    userID,
		Action:    action,
		Result:    result,
		CreatedAt: time.Now().UTC(),
	}
}
