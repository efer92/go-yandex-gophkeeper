package middleware_test

import (
	"context"
	"net"
	"testing"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
)

func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	rl := middleware.NewRateLimiter(rate.Limit(100), 10)
	interceptor := rl.UnaryInterceptor()

	md := metadata.Pairs("x-forwarded-for", "1.2.3.4")
	ctx := metadata.NewIncomingContext(ctxWithToken(""), md)

	for i := 0; i < 5; i++ {
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/auth.AuthService/Login"}, noopHandler)
		require.NoError(t, err, "request %d should succeed within burst", i)
	}
}

func TestRateLimiter_BlocksExcessRequests(t *testing.T) {
	// burst=1 means only 1 request is allowed per IP before being throttled
	rl := middleware.NewRateLimiter(rate.Limit(0), 1)
	interceptor := rl.UnaryInterceptor()

	md := metadata.Pairs("x-forwarded-for", "9.9.9.9")
	ctx := metadata.NewIncomingContext(ctxWithToken(""), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/auth.AuthService/Login"}

	// First request should succeed (uses up the burst)
	_, err := interceptor(ctx, nil, info, noopHandler)
	require.NoError(t, err)

	// Second request should be throttled
	_, err = interceptor(ctx, nil, info, noopHandler)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
}

func TestRateLimiter_NonRateLimitedMethodPassesThrough(t *testing.T) {
	rl := middleware.NewRateLimiter(rate.Limit(0), 0) // zero budget
	interceptor := rl.UnaryInterceptor()

	_, err := interceptor(ctxWithToken(""), nil,
		&grpc.UnaryServerInfo{FullMethod: "/vault.VaultService/ListItems"},
		noopHandler)
	assert.NoError(t, err, "vault methods must not be rate-limited")
}

func TestRateLimiter_UsesPeerAddrWhenNoForwardedFor(t *testing.T) {
	rl := middleware.NewRateLimiter(rate.Limit(0), 1)
	interceptor := rl.UnaryInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/auth.AuthService/Login"}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345},
	})

	_, err := interceptor(ctx, nil, info, noopHandler)
	require.NoError(t, err)
	_, err = interceptor(ctx, nil, info, noopHandler)
	require.Error(t, err)
}

func TestRateLimiter_SeparateIPsHaveSeparateBudgets(t *testing.T) {
	rl := middleware.NewRateLimiter(rate.Limit(0), 1)
	interceptor := rl.UnaryInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/auth.AuthService/Login"}

	ctxA := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-forwarded-for", "1.1.1.1"))
	ctxB := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-forwarded-for", "2.2.2.2"))

	_, err := interceptor(ctxA, nil, info, noopHandler)
	require.NoError(t, err)
	// Different IP still has its own burst available.
	_, err = interceptor(ctxB, nil, info, noopHandler)
	require.NoError(t, err)
}
