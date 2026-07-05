package grpcclient

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
)

func TestNew_Insecure(t *testing.T) {
	c, err := New(&config.Config{ServerAddr: "localhost:50051"})
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NotNil(t, c.Conn())
	require.NotNil(t, c.AuthSvc)
	c.Close()
}

func TestNew_TLSCertMissing(t *testing.T) {
	_, err := New(&config.Config{
		ServerAddr:  "localhost:50051",
		TLSCertPath: "/nonexistent/cert.pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read tls cert")
}

func TestNew_TLSCertInvalid(t *testing.T) {
	f := t.TempDir() + "/bad.pem"
	require.NoError(t, writeFile(f, "not a pem"))
	_, err := New(&config.Config{
		ServerAddr:  "localhost:50051",
		TLSCertPath: f,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse tls cert")
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

func TestWithAuth_NoToken(t *testing.T) {
	c := &Client{cfg: &config.Config{}}
	ctx := c.WithAuth(context.Background())
	md, ok := metadata.FromOutgoingContext(ctx)
	assert.False(t, ok || len(md.Get("authorization")) > 0)
}

func TestWithAuth_WithToken(t *testing.T) {
	c := &Client{cfg: &config.Config{AccessToken: "tok123"}}
	ctx := c.WithAuth(context.Background())
	md, ok := metadata.FromOutgoingContext(ctx)
	require.True(t, ok)
	assert.Equal(t, []string{"Bearer tok123"}, md.Get("authorization"))
}

// fakeInvoker records the auth header it was called with and returns a preset error.
func TestRefreshInterceptor_NoErrorPassesThrough(t *testing.T) {
	cfg := &config.Config{AccessToken: "tok"}
	interceptor := refreshInterceptor(cfg)
	var calls int
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		return nil
	}
	err := interceptor(context.Background(), "/vault.VaultService/List", nil, nil, nil, invoker)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestRefreshInterceptor_NonUnauthenticatedNotRetried(t *testing.T) {
	cfg := &config.Config{AccessToken: "tok", RefreshToken: "rt"}
	interceptor := refreshInterceptor(cfg)
	var calls int
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		return status.Error(codes.Internal, "boom")
	}
	err := interceptor(context.Background(), "/vault.VaultService/List", nil, nil, nil, invoker)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, 1, calls)
}

func TestRefreshInterceptor_SkipsRefreshMethod(t *testing.T) {
	cfg := &config.Config{AccessToken: "tok", RefreshToken: "rt"}
	interceptor := refreshInterceptor(cfg)
	var calls int
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		return status.Error(codes.Unauthenticated, "no")
	}
	err := interceptor(context.Background(), "/auth.AuthService/Refresh", nil, nil, nil, invoker)
	require.Error(t, err)
	// Should not attempt to refresh (would require a 2nd invoker call path); only one call.
	assert.Equal(t, 1, calls)
}

func TestRefreshInterceptor_NoRefreshTokenNoRetry(t *testing.T) {
	cfg := &config.Config{AccessToken: "tok"} // no refresh token
	interceptor := refreshInterceptor(cfg)
	var calls int
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		return status.Error(codes.Unauthenticated, "no")
	}
	err := interceptor(context.Background(), "/vault.VaultService/List", nil, nil, nil, invoker)
	require.Error(t, err)
	assert.Equal(t, 1, calls)
}
