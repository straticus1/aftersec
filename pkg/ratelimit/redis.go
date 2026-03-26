package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements distributed rate limiting using Redis token bucket algorithm
type RedisRateLimiter struct {
	client        *redis.Client
	keyPrefix     string
	maxTokens     int
	refillRate    time.Duration
	tokenLifetime time.Duration
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
// maxTokens: maximum tokens in bucket
// refillRate: how often to add one token (e.g., time.Minute/60 for 60 req/min)
func NewRedisRateLimiter(client *redis.Client, keyPrefix string, maxTokens int, refillRate time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		client:        client,
		keyPrefix:     keyPrefix,
		maxTokens:     maxTokens,
		refillRate:    refillRate,
		tokenLifetime: refillRate * time.Duration(maxTokens) * 2, // 2x max tokens worth of time
	}
}

// Wait blocks until a token is available or context is cancelled
// Uses Redis atomic operations to ensure distributed consistency
func (rl *RedisRateLimiter) Wait(ctx context.Context, identifier string) error {
	key := fmt.Sprintf("%s:%s", rl.keyPrefix, identifier)

	for {
		// Try to consume a token using Lua script for atomicity
		consumed, err := rl.tryConsumeToken(ctx, key)
		if err != nil {
			return fmt.Errorf("rate limiter error: %w", err)
		}

		if consumed {
			return nil
		}

		// Wait before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Continue loop
		}
	}
}

// tryConsumeToken attempts to consume a token using Lua script for atomic operation
// Returns true if token was consumed, false if bucket is empty
func (rl *RedisRateLimiter) tryConsumeToken(ctx context.Context, key string) (bool, error) {
	now := time.Now().UnixMilli()

	// Lua script for atomic token bucket operation
	// This ensures race-free operation across multiple servers
	script := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local max_tokens = tonumber(ARGV[2])
		local refill_rate_ms = tonumber(ARGV[3])
		local token_lifetime_ms = tonumber(ARGV[4])

		-- Get current state
		local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(bucket[1]) or max_tokens
		local last_refill = tonumber(bucket[2]) or now

		-- Calculate tokens to add based on time elapsed
		local elapsed = now - last_refill
		local tokens_to_add = math.floor(elapsed / refill_rate_ms)

		-- Refill tokens
		if tokens_to_add > 0 then
			tokens = math.min(tokens + tokens_to_add, max_tokens)
			last_refill = now
		end

		-- Try to consume a token
		if tokens > 0 then
			tokens = tokens - 1
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
			redis.call('PEXPIRE', key, token_lifetime_ms)
			return 1
		else
			-- Update last check time even if no token consumed
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
			redis.call('PEXPIRE', key, token_lifetime_ms)
			return 0
		end
	`

	result, err := rl.client.Eval(ctx, script, []string{key},
		now,
		rl.maxTokens,
		rl.refillRate.Milliseconds(),
		rl.tokenLifetime.Milliseconds(),
	).Int()

	if err != nil {
		return false, err
	}

	return result == 1, nil
}

// Reset clears the rate limit for a specific identifier
func (rl *RedisRateLimiter) Reset(ctx context.Context, identifier string) error {
	key := fmt.Sprintf("%s:%s", rl.keyPrefix, identifier)
	return rl.client.Del(ctx, key).Err()
}

// GetTokens returns the current number of tokens available for an identifier
func (rl *RedisRateLimiter) GetTokens(ctx context.Context, identifier string) (int, error) {
	key := fmt.Sprintf("%s:%s", rl.keyPrefix, identifier)
	now := time.Now().UnixMilli()

	script := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local max_tokens = tonumber(ARGV[2])
		local refill_rate_ms = tonumber(ARGV[3])

		local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(bucket[1]) or max_tokens
		local last_refill = tonumber(bucket[2]) or now

		local elapsed = now - last_refill
		local tokens_to_add = math.floor(elapsed / refill_rate_ms)

		if tokens_to_add > 0 then
			tokens = math.min(tokens + tokens_to_add, max_tokens)
		end

		return tokens
	`

	result, err := rl.client.Eval(ctx, script, []string{key},
		now,
		rl.maxTokens,
		rl.refillRate.Milliseconds(),
	).Int()

	if err != nil {
		return 0, err
	}

	return result, nil
}

// Close closes the Redis client connection
func (rl *RedisRateLimiter) Close() error {
	if rl.client != nil {
		return rl.client.Close()
	}
	return nil
}
