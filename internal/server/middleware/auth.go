// Package middleware provides gRPC server interceptors for GophKeeper.
package middleware

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
)

type contextKey string

const (
	// contextKeyUserID is the context key for the authenticated user ID.
	contextKeyUserID contextKey = "user_id"
)

// publicMethods are RPC paths that do not require authentication.
var publicMethods = map[string]bool{
	"/auth.AuthService/Register":  true,
	"/auth.AuthService/Login":     true,
	"/auth.AuthService/Refresh":   true,
	"/auth.AuthService/VerifyMFA": true,
}

// AuthInterceptor returns a gRPC UnaryServerInterceptor that validates JWT tokens.
func AuthInterceptor(jwtMgr *jwtpkg.Manager) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		ctx, err := extractAndValidate(ctx, jwtMgr)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// AuthStreamInterceptor returns a gRPC StreamServerInterceptor that validates JWT tokens.
func AuthStreamInterceptor(jwtMgr *jwtpkg.Manager) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}
		ctx, err := extractAndValidate(ss.Context(), jwtMgr)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ss, ctx})
	}
}

func extractAndValidate(ctx context.Context, jwtMgr *jwtpkg.Manager) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}
	tokenStr := strings.TrimPrefix(vals[0], "Bearer ")
	claims, err := jwtMgr.ParseAccessToken(tokenStr)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	ctx = context.WithValue(ctx, contextKeyUserID, claims.Subject)
	return ctx, nil
}

// ContextWithUserID returns a new context with the given user ID stored.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, contextKeyUserID, userID)
}

// UserIDFromContext extracts the authenticated user ID from ctx.
func UserIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(contextKeyUserID).(string)
	return v, ok
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }
