// Package grpcclient provides a gRPC client with JWT auto-refresh.
package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
)

// Client wraps a gRPC connection with automatic JWT refresh.
type Client struct {
	conn    *grpc.ClientConn
	cfg     *config.Config
	AuthSvc authpb.AuthServiceClient
}

// New dials the server and returns a Client.
func New(cfg *config.Config) (*Client, error) {
	var dialOpt grpc.DialOption
	if cfg.TLSCertPath != "" {
		certPool := x509.NewCertPool()
		cert, err := os.ReadFile(cfg.TLSCertPath)
		if err != nil {
			return nil, fmt.Errorf("read tls cert: %w", err)
		}
		if !certPool.AppendCertsFromPEM(cert) {
			return nil, fmt.Errorf("parse tls cert")
		}
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: certPool}))
	} else {
		// TLS is always enabled to encrypt traffic in transit.
		// InsecureSkipVerify is acceptable only with self-signed certificates;
		// for production, set TLSCertPath for full server verification.
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed certs require skip verify
		}))
	}

	conn, err := grpc.NewClient(cfg.ServerAddr, dialOpt,
		grpc.WithUnaryInterceptor(refreshInterceptor(cfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.ServerAddr, err)
	}
	return &Client{
		conn:    conn,
		cfg:     cfg,
		AuthSvc: authpb.NewAuthServiceClient(conn),
	}, nil
}

// Conn returns the underlying gRPC connection for constructing other service clients.
func (c *Client) Conn() *grpc.ClientConn { return c.conn }

// Close terminates the connection.
func (c *Client) Close() { _ = c.conn.Close() }

// WithAuth returns a context with the current access token in gRPC metadata.
func (c *Client) WithAuth(ctx context.Context) context.Context {
	if c.cfg.AccessToken == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.cfg.AccessToken)
}

// refreshInterceptor catches Unauthenticated errors, refreshes the token, and retries once.
// It only refreshes on codes.Unauthenticated to avoid recursive calls on connection errors.
func refreshInterceptor(cfg *config.Config) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		if cfg.AccessToken != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.AccessToken)
		}
		err := invoker(ctx, method, req, reply, cc, opts...)
		// Only attempt token refresh on Unauthenticated, and only when this is not itself
		// a Refresh call (avoids infinite recursion) and a refresh token is available.
		if err == nil || cfg.RefreshToken == "" || method == "/auth.AuthService/Refresh" {
			return err
		}
		if status.Code(err) != codes.Unauthenticated {
			return err
		}

		// Attempt token refresh.
		refreshCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		authClient := authpb.NewAuthServiceClient(cc)
		resp, rerr := authClient.Refresh(refreshCtx, authpb.RefreshRequest_builder{
			RefreshToken: cfg.RefreshToken,
		}.Build())
		if rerr != nil {
			return err // return original error
		}
		cfg.AccessToken = resp.GetAccessToken()
		_ = config.Save(cfg)

		ctx = metadata.AppendToOutgoingContext(context.Background(),
			"authorization", "Bearer "+cfg.AccessToken)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
