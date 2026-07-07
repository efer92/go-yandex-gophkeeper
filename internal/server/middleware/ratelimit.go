package middleware

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// rateLimitedMethods are auth endpoints that require per-IP rate limiting.
var rateLimitedMethods = map[string]bool{
	"/auth.AuthService/Register":  true,
	"/auth.AuthService/Login":     true,
	"/auth.AuthService/VerifyMFA": true,
}

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter holds per-IP token bucket limiters for auth endpoints.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	r        rate.Limit
	b        int
}

// NewRateLimiter creates a RateLimiter allowing r events/sec with burst b per IP.
// Reasonable defaults: r=5, b=10 (10 attempts burst, then 5/sec).
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*ipLimiter),
		r:        r,
		b:        b,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.limiters[ip]
	if !ok {
		entry = &ipLimiter{limiter: rate.NewLimiter(rl.r, rl.b)}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// cleanup removes stale IP entries every minute.
func (rl *RateLimiter) cleanup() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		for ip, entry := range rl.limiters {
			if time.Since(entry.lastSeen) > 5*time.Minute {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func peerIP(ctx context.Context) string {
	// Try X-Forwarded-For first (grpc-gateway sets this).
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-forwarded-for"); len(vals) > 0 {
			return vals[0]
		}
	}
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}

// UnaryInterceptor rate-limits auth endpoints by client IP.
func (rl *RateLimiter) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if rateLimitedMethods[info.FullMethod] {
			ip := peerIP(ctx)
			if !rl.getLimiter(ip).Allow() {
				return nil, status.Error(codes.ResourceExhausted, "too many requests — please slow down")
			}
		}
		return handler(ctx, req)
	}
}
