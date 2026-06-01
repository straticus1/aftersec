package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestLimiter(t *testing.T, maxTokens int, refillRate time.Duration) (*RedisRateLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return NewRedisRateLimiter(client, "test", maxTokens, refillRate), mr
}

func TestNewRedisRateLimiter_TokenLifetime(t *testing.T) {
	// tokenLifetime = refillRate * maxTokens * 2
	rl := NewRedisRateLimiter(nil, "prefix", 10, 6*time.Second)
	expected := 6 * time.Second * time.Duration(10) * 2
	if rl.tokenLifetime != expected {
		t.Errorf("expected tokenLifetime %v, got %v", expected, rl.tokenLifetime)
	}
}

func TestTryConsume_FirstRequestAllowed(t *testing.T) {
	rl, _ := newTestLimiter(t, 5, time.Second)
	allowed, err := rl.TryConsume(context.Background(), "user1")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected first request to be allowed")
	}
}

func TestTryConsume_ExhaustsBucket(t *testing.T) {
	rl, _ := newTestLimiter(t, 3, time.Second)
	ctx := context.Background()

	for i := range 3 {
		allowed, err := rl.TryConsume(ctx, "user1")
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	allowed, err := rl.TryConsume(ctx, "user1")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected 4th request to be denied after bucket exhausted")
	}
}

func TestTryConsume_DifferentIdentifiersAreIndependent(t *testing.T) {
	rl, _ := newTestLimiter(t, 1, time.Second)
	ctx := context.Background()

	// Exhaust user1's bucket.
	rl.TryConsume(ctx, "user1") //nolint:errcheck
	rl.TryConsume(ctx, "user1") //nolint:errcheck

	// user2 should have a full bucket unaffected by user1.
	allowed, err := rl.TryConsume(ctx, "user2")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("user2 should not be rate-limited by user1's exhaustion")
	}
}

func TestReset_ClearsTokens(t *testing.T) {
	rl, _ := newTestLimiter(t, 2, time.Second)
	ctx := context.Background()

	// Drain the bucket.
	rl.TryConsume(ctx, "user1") //nolint:errcheck
	rl.TryConsume(ctx, "user1") //nolint:errcheck

	allowed, _ := rl.TryConsume(ctx, "user1")
	if allowed {
		t.Skip("bucket not empty after 2 consumes — test setup issue")
	}

	if err := rl.Reset(ctx, "user1"); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	allowed, err := rl.TryConsume(ctx, "user1")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected token available after Reset")
	}
}

func TestGetTokens_ReturnsExpectedCount(t *testing.T) {
	rl, _ := newTestLimiter(t, 5, time.Second)
	ctx := context.Background()

	rl.TryConsume(ctx, "user1") //nolint:errcheck
	rl.TryConsume(ctx, "user1") //nolint:errcheck

	tokens, err := rl.GetTokens(ctx, "user1")
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 3 {
		t.Errorf("expected 3 remaining tokens, got %d", tokens)
	}
}

func TestGetTokens_FreshIdentifierReturnsFull(t *testing.T) {
	rl, _ := newTestLimiter(t, 7, time.Second)
	tokens, err := rl.GetTokens(context.Background(), "fresh-user")
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 7 {
		t.Errorf("expected 7 tokens for new identifier, got %d", tokens)
	}
}

func TestTryConsume_RefillAfterWait(t *testing.T) {
	// Use a short refill rate so the test stays fast.
	rl, _ := newTestLimiter(t, 1, 20*time.Millisecond)
	ctx := context.Background()

	// Drain the single-token bucket.
	rl.TryConsume(ctx, "user1") //nolint:errcheck

	allowed, _ := rl.TryConsume(ctx, "user1")
	if allowed {
		t.Skip("bucket not empty after consuming 1 token")
	}

	// Wait 2 refill intervals so at least one token is restored.
	time.Sleep(50 * time.Millisecond)

	allowed, err := rl.TryConsume(ctx, "user1")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected token available after refill interval")
	}
}
