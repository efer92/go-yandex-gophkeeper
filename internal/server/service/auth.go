// Package service implements GophKeeper business logic.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/audit"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles user registration and authentication.
type AuthService struct {
	store  storage.Store
	jwtMgr *jwtpkg.Manager
}

// NewAuthService creates an AuthService.
func NewAuthService(store storage.Store, jwtMgr *jwtpkg.Manager) *AuthService {
	return &AuthService{store: store, jwtMgr: jwtMgr}
}

// RegisterInput holds registration parameters.
type RegisterInput struct {
	Username      string
	Email         string
	Password      string
	VaultSymKey   []byte
	KDFParamsJSON string
}

// RegisterResult holds the new user ID.
type RegisterResult struct {
	UserID string
}

// Register creates a new user account.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (RegisterResult, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), 12)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("hash password: %w", err)
	}
	user, err := s.store.Users().Create(ctx, storage.User{
		Username:     in.Username,
		Email:        in.Email,
		PasswordHash: string(hash),
		VaultSymKey:  in.VaultSymKey,
		KDFParams:    in.KDFParamsJSON,
	})
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return RegisterResult{}, ErrUserExists
		}
		return RegisterResult{}, fmt.Errorf("create user: %w", err)
	}
	s.logAudit(ctx, user.ID, audit.ActionRegister, audit.ResultOK)
	return RegisterResult{UserID: user.ID}, nil
}

// LoginInput holds login parameters.
type LoginInput struct {
	Username string
	Password string
}

// LoginResult holds session tokens and vault key material.
type LoginResult struct {
	AccessToken   string
	RefreshToken  string
	SessionID     string
	NeedsMFA      bool
	KDFParamsJSON string
	VaultSymKey   []byte
}

// dummyHash is a pre-computed bcrypt hash used to prevent username enumeration via timing.
// When a user is not found we still run CompareHashAndPassword so the response time is
// indistinguishable from a wrong-password response for an existing user.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-constant-time-sentinel"), 12)

// Login authenticates a user and issues session tokens.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	user, err := s.store.Users().GetByUsername(ctx, in.Username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Run bcrypt anyway to prevent username enumeration via response-time differences.
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(in.Password))
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, fmt.Errorf("get user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(in.Password)); err != nil {
		s.logAudit(ctx, user.ID, audit.ActionLoginFailed, audit.ResultDenied)
		return LoginResult{}, ErrInvalidCredentials
	}

	refreshToken, err := s.jwtMgr.IssueRefreshToken(user.ID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("issue refresh token: %w", err)
	}

	session, err := s.store.Sessions().Create(ctx, storage.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
		MFAVerified:  !user.MFARequired,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("create session: %w", err)
	}

	var accessToken string
	if !user.MFARequired {
		accessToken, err = s.jwtMgr.IssueAccessToken(user.ID, false)
		if err != nil {
			return LoginResult{}, fmt.Errorf("issue access token: %w", err)
		}
		s.logAudit(ctx, user.ID, audit.ActionLogin, audit.ResultOK)
	}

	return LoginResult{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		SessionID:     session.ID,
		NeedsMFA:      user.MFARequired,
		KDFParamsJSON: user.KDFParams,
		VaultSymKey:   user.VaultSymKey,
	}, nil
}

// Refresh issues a new access token from a valid refresh token.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (string, error) {
	session, err := s.store.Sessions().GetByRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if time.Now().After(session.ExpiresAt) {
		return "", ErrInvalidCredentials
	}
	accessToken, err := s.jwtMgr.IssueAccessToken(session.UserID, session.MFAVerified)
	if err != nil {
		return "", fmt.Errorf("issue access token: %w", err)
	}
	s.logAudit(ctx, session.UserID, audit.ActionRefresh, audit.ResultOK)
	return accessToken, nil
}

// Logout deletes the session associated with the refresh token.
func (s *AuthService) Logout(ctx context.Context, userID, refreshToken string) error {
	err := s.store.Sessions().Delete(ctx, refreshToken)
	s.logAudit(ctx, userID, audit.ActionLogout, audit.ResultOK)
	return err
}

func (s *AuthService) logAudit(ctx context.Context, userID string, action audit.Action, result audit.Result) {
	e := audit.New(userID, action, result)
	_ = s.store.Audit().Append(ctx, storage.AuditEntry{
		UserID:    e.UserID,
		Action:    string(e.Action),
		Result:    string(e.Result),
		IP:        peerIP(ctx),
		CreatedAt: e.CreatedAt,
	})
}

var (
	// ErrUserExists is returned when registering a duplicate username/email.
	ErrUserExists = errors.New("user already exists")
	// ErrInvalidCredentials is returned on bad username/password or expired session.
	ErrInvalidCredentials = errors.New("invalid credentials")
)
