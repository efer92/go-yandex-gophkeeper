package testutil

import (
	"bytes"
	"net"
	"os"
	"testing"

	"google.golang.org/grpc"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	syncpb "github.com/efer92/go-yandex-gophkeeper/gen/sync"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	clientcfg "github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/handler"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
)

// TestServer is an in-process gRPC server backed by MockStore, intended for
// end-to-end client command tests.
type TestServer struct {
	Addr    string
	JWT     *jwtpkg.Manager
	Store   *MockStore
	grpcSrv *grpc.Server
	lis     net.Listener
}

// NewTestServer starts a gRPC server on an ephemeral localhost port wired with
// the real auth/vault/sync handlers and the JWT auth interceptor. Call Stop when done.
func NewTestServer() (*TestServer, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	store := NewMockStore()
	jwtMgr := NewTestJWT()

	authSvc := service.NewAuthService(store, jwtMgr)
	mfaSvc := service.NewMFAService(store, jwtMgr, "GophKeeper")
	syncSvc := service.NewSyncService()
	vaultSvc := service.NewVaultService(store, syncSvc)

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(middleware.AuthInterceptor(jwtMgr)),
		grpc.StreamInterceptor(middleware.AuthStreamInterceptor(jwtMgr)),
	)
	authpb.RegisterAuthServiceServer(srv, handler.NewAuthHandler(authSvc, mfaSvc))
	vaultpb.RegisterVaultServiceServer(srv, handler.NewVaultHandler(vaultSvc))
	syncpb.RegisterSyncServiceServer(srv, handler.NewSyncHandler(syncSvc, vaultSvc))

	ts := &TestServer{
		Addr:    lis.Addr().String(),
		JWT:     jwtMgr,
		Store:   store,
		grpcSrv: srv,
		lis:     lis,
	}
	go func() { _ = srv.Serve(lis) }()
	return ts, nil
}

// Token issues a valid access token for the given user ID.
func (ts *TestServer) Token(userID string) string {
	tok, _ := ts.JWT.IssueAccessToken(userID, true)
	return tok
}

// Stop gracefully shuts the server down.
func (ts *TestServer) Stop() { ts.grpcSrv.Stop() }

// SetupClientConfig writes a client config for userID into a temp HOME directory
// and sets the HOME env var for the test. It is a convenience wrapper used by
// CLI command tests that need to talk to the test server.
func (ts *TestServer) SetupClientConfig(t *testing.T, userID string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := &clientcfg.Config{
		ServerAddr:  ts.Addr,
		AccessToken: ts.Token(userID),
		Username:    userID,
	}
	if err := clientcfg.Save(cfg); err != nil {
		t.Fatalf("setup client config: %v", err)
	}
}

// CaptureOutput runs fn while replacing os.Stdout with a pipe, then returns the
// combined captured output. Use in tests where commands write directly to os.Stdout.
func CaptureOutput(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// WithStdin replaces os.Stdin with a pipe pre-filled with input for the duration of fn.
func WithStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	_, _ = w.WriteString(input)
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = old }()
	fn()
}
