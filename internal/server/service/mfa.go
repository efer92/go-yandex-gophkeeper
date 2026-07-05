package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/audit"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFAService handles TOTP enrollment, confirmation, and verification.
type MFAService struct {
	store  storage.Store
	jwtMgr *jwtpkg.Manager
	issuer string
}

// NewMFAService creates a MFAService.
func NewMFAService(store storage.Store, jwtMgr *jwtpkg.Manager, issuer string) *MFAService {
	return &MFAService{store: store, jwtMgr: jwtMgr, issuer: issuer}
}

// EnrollTOTPResult holds the TOTP ID, secret, and otpauth URL for QR display.
type EnrollTOTPResult struct {
	TOTPID     string
	Secret     string
	OTPAuthURL string
}

// EnrollTOTP generates a new TOTP secret and stores it (unconfirmed).
func (s *MFAService) EnrollTOTP(ctx context.Context, userID, label string) (EnrollTOTPResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: label,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return EnrollTOTPResult{}, fmt.Errorf("generate totp key: %w", err)
	}
	rec, err := s.store.MFA().CreateTOTP(ctx, storage.TOTPRecord{
		UserID: userID,
		Secret: key.Secret(),
		Label:  label,
	})
	if err != nil {
		return EnrollTOTPResult{}, fmt.Errorf("store totp: %w", err)
	}
	return EnrollTOTPResult{
		TOTPID:     rec.ID,
		Secret:     key.Secret(),
		OTPAuthURL: key.URL(),
	}, nil
}

// ConfirmTOTP verifies a TOTP code and marks the record as confirmed,
// then enables MFA on the user's account.
func (s *MFAService) ConfirmTOTP(ctx context.Context, userID, totpID, code string) error {
	rec, err := s.store.MFA().GetTOTPByID(ctx, totpID, userID)
	if err != nil {
		return ErrMFAInvalid
	}
	valid, err := totp.ValidateCustom(code, rec.Secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return ErrMFAInvalid
	}
	if err := s.store.MFA().ConfirmTOTP(ctx, totpID); err != nil {
		return fmt.Errorf("confirm totp: %w", err)
	}
	if err := s.store.Users().SetMFARequired(ctx, userID, true); err != nil {
		return fmt.Errorf("enable mfa: %w", err)
	}
	s.logAudit(ctx, userID, audit.ActionMFAEnroll, audit.ResultOK)
	return nil
}

// VerifyMFAInput holds the session ID and TOTP code for MFA verification.
type VerifyMFAInput struct {
	SessionID string
	TOTPCode  string
	UserID    string
}

// VerifyMFAResult holds freshly issued tokens after successful MFA.
type VerifyMFAResult struct {
	AccessToken  string
	RefreshToken string
}

// VerifyTOTP checks a TOTP code against all confirmed TOTP records for the user.
func (s *MFAService) VerifyTOTP(ctx context.Context, in VerifyMFAInput) (VerifyMFAResult, error) {
	records, err := s.store.MFA().ListTOTP(ctx, in.UserID)
	if err != nil {
		return VerifyMFAResult{}, fmt.Errorf("list totp: %w", err)
	}

	var matched bool
	for _, rec := range records {
		ok, _ := totp.ValidateCustom(in.TOTPCode, rec.Secret, time.Now(), totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if ok {
			matched = true
			break
		}
	}
	if !matched {
		s.logAudit(ctx, in.UserID, audit.ActionMFAFailed, audit.ResultDenied)
		return VerifyMFAResult{}, ErrMFAInvalid
	}

	if err := s.store.Sessions().SetMFAVerified(ctx, in.SessionID); err != nil {
		return VerifyMFAResult{}, fmt.Errorf("set mfa verified: %w", err)
	}

	refreshToken, err := s.jwtMgr.IssueRefreshToken(in.UserID)
	if err != nil {
		return VerifyMFAResult{}, err
	}
	_, err = s.store.Sessions().Create(ctx, storage.Session{
		UserID:       in.UserID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
		MFAVerified:  true,
	})
	if err != nil {
		return VerifyMFAResult{}, fmt.Errorf("create mfa session: %w", err)
	}

	accessToken, err := s.jwtMgr.IssueAccessToken(in.UserID, true)
	if err != nil {
		return VerifyMFAResult{}, err
	}

	s.logAudit(ctx, in.UserID, audit.ActionMFAVerify, audit.ResultOK)
	return VerifyMFAResult{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *MFAService) logAudit(ctx context.Context, userID string, action audit.Action, result audit.Result) {
	e := audit.New(userID, action, result)
	_ = s.store.Audit().Append(ctx, storage.AuditEntry{
		UserID:    e.UserID,
		Action:    string(e.Action),
		Result:    string(e.Result),
		IP:        peerIP(ctx),
		CreatedAt: e.CreatedAt,
	})
}

// ErrMFAInvalid is returned when an MFA code is wrong or expired.
var ErrMFAInvalid = errors.New("invalid MFA code")
