package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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
	Addr       string
	JWT        *jwtpkg.Manager
	Store      *MockStore
	CertPath   string
	grpcSrv    *grpc.Server
	lis        net.Listener
	cleanupDir string
}

// NewTestServer starts a TLS-enabled gRPC server on an ephemeral localhost port
// wired with the real auth/vault/sync handlers and the JWT auth interceptor.
// Call Stop when done.
func NewTestServer() (*TestServer, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
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
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS13,
		})),
		grpc.UnaryInterceptor(middleware.AuthInterceptor(jwtMgr)),
		grpc.StreamInterceptor(middleware.AuthStreamInterceptor(jwtMgr)),
	)
	authpb.RegisterAuthServiceServer(srv, handler.NewAuthHandler(authSvc, mfaSvc))
	vaultpb.RegisterVaultServiceServer(srv, handler.NewVaultHandler(vaultSvc))
	syncpb.RegisterSyncServiceServer(srv, handler.NewSyncHandler(syncSvc, vaultSvc))

	tmpDir, err := os.MkdirTemp("", "gophkeeper-test-*")
	if err != nil {
		return nil, err
	}
	certPath := filepath.Join(tmpDir, "server.crt")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	ts := &TestServer{
		Addr:       lis.Addr().String(),
		JWT:        jwtMgr,
		Store:      store,
		CertPath:   certPath,
		grpcSrv:    srv,
		lis:        lis,
		cleanupDir: tmpDir,
	}
	go func() { _ = srv.Serve(lis) }()
	return ts, nil
}

// Token issues a valid access token for the given user ID.
func (ts *TestServer) Token(userID string) string {
	tok, _ := ts.JWT.IssueAccessToken(userID, true)
	return tok
}

// Stop gracefully shuts the server down and removes temp cert files.
func (ts *TestServer) Stop() {
	ts.grpcSrv.Stop()
	if ts.cleanupDir != "" {
		_ = os.RemoveAll(ts.cleanupDir)
	}
}

// SetupClientConfig writes a client config for userID into a temp HOME directory
// and sets the HOME env var for the test. It includes the TLS cert path so the
// client can verify the test server's certificate.
func (ts *TestServer) SetupClientConfig(t *testing.T, userID string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := &clientcfg.Config{
		ServerAddr:  ts.Addr,
		TLSCertPath: ts.CertPath,
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

// generateSelfSignedCert creates a self-signed TLS certificate and key in PEM format.
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	var certBuf, keyBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, nil, err
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
