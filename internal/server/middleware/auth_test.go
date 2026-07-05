package middleware_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testJWT() *jwtpkg.Manager {
	return jwtpkg.NewManager(jwtpkg.Config{
		Secret:         []byte("middleware-test-secret-32-bytes!!"),
		AccessTokenTTL: time.Hour,
	})
}

func ctxWithToken(t string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+t)
	return metadata.NewIncomingContext(context.Background(), md)
}

func noopHandler(_ context.Context, req any) (any, error) { return req, nil }

func TestAuthInterceptor_ValidToken(t *testing.T) {
	mgr := testJWT()
	tok, err := mgr.IssueAccessToken("user-42", false)
	require.NoError(t, err)

	interceptor := middleware.AuthInterceptor(mgr)
	resp, err := interceptor(ctxWithToken(tok), nil, &grpc.UnaryServerInfo{FullMethod: "/vault.VaultService/ListItems"},
		func(ctx context.Context, req any) (any, error) {
			uid, ok := middleware.UserIDFromContext(ctx)
			assert.True(t, ok)
			assert.Equal(t, "user-42", uid)
			return nil, nil
		})
	assert.NoError(t, err)
	_ = resp
}

func TestAuthInterceptor_MissingToken(t *testing.T) {
	mgr := testJWT()
	interceptor := middleware.AuthInterceptor(mgr)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/vault.VaultService/ListItems"}, noopHandler)
	assert.Error(t, err)
}

func TestAuthInterceptor_ExpiredToken(t *testing.T) {
	mgr := jwtpkg.NewManager(jwtpkg.Config{
		Secret:         []byte("middleware-test-secret-32-bytes!!"),
		AccessTokenTTL: -time.Second,
	})
	tok, _ := mgr.IssueAccessToken("user-1", false)
	interceptor := middleware.AuthInterceptor(testJWT())
	_, err := interceptor(ctxWithToken(tok), nil,
		&grpc.UnaryServerInfo{FullMethod: "/vault.VaultService/ListItems"}, noopHandler)
	assert.Error(t, err)
}

func TestAuthInterceptor_PublicMethod_NoTokenRequired(t *testing.T) {
	mgr := testJWT()
	interceptor := middleware.AuthInterceptor(mgr)
	ctx := context.Background() // no metadata
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/auth.AuthService/Login"}, noopHandler)
	assert.NoError(t, err)
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

func TestAuthStreamInterceptor_PublicMethod(t *testing.T) {
	mgr := testJWT()
	interceptor := middleware.AuthStreamInterceptor(mgr)
	called := false
	err := interceptor(nil, &fakeServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: "/auth.AuthService/Login"},
		func(srv any, ss grpc.ServerStream) error { called = true; return nil })
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestAuthStreamInterceptor_ValidToken(t *testing.T) {
	mgr := testJWT()
	tok, _ := mgr.IssueAccessToken("user-7", true)
	interceptor := middleware.AuthStreamInterceptor(mgr)

	var gotUID string
	err := interceptor(nil, &fakeServerStream{ctx: ctxWithToken(tok)},
		&grpc.StreamServerInfo{FullMethod: "/sync.SyncService/Subscribe"},
		func(srv any, ss grpc.ServerStream) error {
			uid, _ := middleware.UserIDFromContext(ss.Context())
			gotUID = uid
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, "user-7", gotUID)
}

func TestAuthStreamInterceptor_MissingToken(t *testing.T) {
	mgr := testJWT()
	interceptor := middleware.AuthStreamInterceptor(mgr)
	err := interceptor(nil, &fakeServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{})},
		&grpc.StreamServerInfo{FullMethod: "/sync.SyncService/Subscribe"},
		func(srv any, ss grpc.ServerStream) error { return nil })
	assert.Error(t, err)
}
