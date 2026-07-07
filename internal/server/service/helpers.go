package service

import (
	"context"

	"google.golang.org/grpc/peer"
)

// peerIP extracts the remote IP address from a gRPC context.
// Returns an empty string if peer info is unavailable.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	return p.Addr.String()
}
