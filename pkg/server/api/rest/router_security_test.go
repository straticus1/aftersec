package rest

// Threats: a rate-limit backend outage must not bypass abuse controls.
// This does not cover Redis availability or distributed consistency.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aftersec/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
)

func TestWithRateLimit_RedisErrorFailsClosed(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  10 * time.Millisecond,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 10 * time.Millisecond,
		MaxRetries:   0,
	})
	defer redisClient.Close()

	limiter := ratelimit.NewRedisRateLimiter(redisClient, "test", 1, time.Minute)
	called := false
	handler := (&Router{}).withRateLimit(limiter, func(w http.ResponseWriter, req *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	resp := httptest.NewRecorder()
	handler(resp, req)

	if called {
		t.Fatal("fail-open: protected handler ran after rate limiter error")
	}
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
	}
}
