package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
)

const (
	DarkAPIBaseURL     = "https://api.darkapi.io/v1"
	maxRetries         = 3
	initialBackoff     = 1 * time.Second
	maxBackoff         = 30 * time.Second
	rateLimitPerMinute = 60 // API calls per minute
)

// RateLimiter interface for both local and distributed rate limiting
type RateLimiter interface {
	Wait(ctx context.Context, identifier string) error
}

// DarkAPIClient handles interactions with DarkAPI.io threat intelligence
type DarkAPIClient struct {
	apiKey            string
	httpClient        *http.Client
	localRateLimiter  *localRateLimiter
	redisRateLimiter  *ratelimit.RedisRateLimiter
	useRedis          bool
	rateLimitIdentity string // Identifier for distributed rate limiting (e.g., "global" or tenant ID)
}

// localRateLimiter implements in-memory token bucket rate limiting
// This is suitable for single-server deployments
type localRateLimiter struct {
	tokens    int
	maxTokens int
	mu        sync.Mutex
	ticker    *time.Ticker
	done      chan bool
}

// newLocalRateLimiter creates a local rate limiter with specified requests per minute
func newLocalRateLimiter(requestsPerMinute int) *localRateLimiter {
	rl := &localRateLimiter{
		tokens:    requestsPerMinute,
		maxTokens: requestsPerMinute,
		ticker:    time.NewTicker(time.Minute / time.Duration(requestsPerMinute)),
		done:      make(chan bool),
	}

	go func() {
		for {
			select {
			case <-rl.ticker.C:
				rl.mu.Lock()
				if rl.tokens < rl.maxTokens {
					rl.tokens++
				}
				rl.mu.Unlock()
			case <-rl.done:
				return
			}
		}
	}()

	return rl
}

// Wait blocks until a token is available (implements RateLimiter interface)
func (rl *localRateLimiter) Wait(ctx context.Context, identifier string) error {
	for {
		rl.mu.Lock()
		if rl.tokens > 0 {
			rl.tokens--
			rl.mu.Unlock()
			return nil
		}
		rl.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Continue loop
		}
	}
}

// stop stops the rate limiter
func (rl *localRateLimiter) stop() {
	rl.ticker.Stop()
	close(rl.done)
}

// ClientOption is a functional option for configuring DarkAPIClient
type ClientOption func(*DarkAPIClient) error

// WithRedisRateLimiter configures the client to use Redis-based distributed rate limiting
// This is required for production multi-server deployments
func WithRedisRateLimiter(redisClient *redis.Client, identifier string) ClientOption {
	return func(c *DarkAPIClient) error {
		if redisClient == nil {
			return fmt.Errorf("redis client cannot be nil")
		}
		c.redisRateLimiter = ratelimit.NewRedisRateLimiter(
			redisClient,
			"darkapi:ratelimit",
			rateLimitPerMinute,
			time.Minute/time.Duration(rateLimitPerMinute),
		)
		c.useRedis = true
		c.rateLimitIdentity = identifier
		return nil
	}
}

// NewDarkAPIClient creates a new DarkAPI.io client with retry logic and rate limiting
// By default, uses local in-memory rate limiting (suitable for single-server deployments)
// For production multi-server deployments, use WithRedisRateLimiter option
func NewDarkAPIClient(apiKey string, opts ...ClientOption) (*DarkAPIClient, error) {
	client := &DarkAPIClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		localRateLimiter:  newLocalRateLimiter(rateLimitPerMinute),
		useRedis:          false,
		rateLimitIdentity: "global",
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, fmt.Errorf("failed to apply client option: %w", err)
		}
	}

	return client, nil
}

// Close stops the rate limiter and closes connections
func (c *DarkAPIClient) Close() error {
	if c.localRateLimiter != nil {
		c.localRateLimiter.stop()
	}
	if c.redisRateLimiter != nil {
		return c.redisRateLimiter.Close()
	}
	return nil
}

// BreachedAccount represents a compromised credential
type BreachedAccount struct {
	Email       string    `json:"email"`
	Source      string    `json:"source"`
	BreachDate  time.Time `json:"breach_date"`
	DataClasses []string  `json:"data_classes"`
	Password    string    `json:"password,omitempty"`
	Domain      string    `json:"domain"`
	Verified    bool      `json:"verified"`
}

// ThreatIOC represents an Indicator of Compromise
type ThreatIOC struct {
	Type        string    `json:"type"` // hash, ip, domain, url
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Severity    string    `json:"severity"` // critical, high, medium, low
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
}

// DarkWebMention represents a mention on dark web forums/marketplaces
type DarkWebMention struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"` // forum, marketplace, paste, telegram
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	Author      string    `json:"author"`
	Timestamp   time.Time `json:"timestamp"`
	URL         string    `json:"url"`
	Relevance   float64   `json:"relevance"` // 0.0-1.0
	Keywords    []string  `json:"keywords"`
}

// doRequestWithRetry executes an HTTP request with exponential backoff retry logic
func (c *DarkAPIClient) doRequestWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Apply rate limiting (local or distributed)
	if c.useRedis && c.redisRateLimiter != nil {
		if err := c.redisRateLimiter.Wait(ctx, c.rateLimitIdentity); err != nil {
			return nil, fmt.Errorf("distributed rate limit wait failed: %w", err)
		}
	} else if c.localRateLimiter != nil {
		if err := c.localRateLimiter.Wait(ctx, ""); err != nil {
			return nil, fmt.Errorf("local rate limit wait failed: %w", err)
		}
	}

	var lastErr error
	backoff := initialBackoff

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait with exponential backoff
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Success or non-retryable error
		if resp.StatusCode < 500 {
			return resp, nil
		}

		// Server error - retry
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastErr = fmt.Errorf("server error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}

// CheckBreachedEmail checks if an email has been compromised
func (c *DarkAPIClient) CheckBreachedEmail(ctx context.Context, email string) ([]BreachedAccount, error) {
	endpoint := fmt.Sprintf("%s/breaches/email/%s", DarkAPIBaseURL, email)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequestWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []BreachedAccount{}, nil
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var breaches []BreachedAccount
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return breaches, nil
}

// CheckDomainBreaches checks if any accounts from a domain have been breached
func (c *DarkAPIClient) CheckDomainBreaches(ctx context.Context, domain string) ([]BreachedAccount, error) {
	endpoint := fmt.Sprintf("%s/breaches/domain/%s", DarkAPIBaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequestWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []BreachedAccount{}, nil
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var breaches []BreachedAccount
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return breaches, nil
}

// CheckIOC checks if a hash, IP, or domain is a known threat indicator
func (c *DarkAPIClient) CheckIOC(ctx context.Context, iocType, value string) (*ThreatIOC, error) {
	endpoint := fmt.Sprintf("%s/ioc/%s/%s", DarkAPIBaseURL, iocType, value)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequestWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var ioc ThreatIOC
	if err := json.NewDecoder(resp.Body).Decode(&ioc); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &ioc, nil
}

// SearchDarkWeb searches dark web forums, marketplaces, and pastes for keywords
func (c *DarkAPIClient) SearchDarkWeb(ctx context.Context, keywords []string) ([]DarkWebMention, error) {
	endpoint := fmt.Sprintf("%s/darkweb/search", DarkAPIBaseURL)

	payload := map[string]interface{}{
		"keywords": keywords,
		"sources":  []string{"forum", "marketplace", "paste", "telegram"},
		"days":     30,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequestWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var mentions []DarkWebMention
	if err := json.NewDecoder(resp.Body).Decode(&mentions); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return mentions, nil
}

// CheckFileHash checks if a file hash is known malware
func (c *DarkAPIClient) CheckFileHash(ctx context.Context, hash string) (*ThreatIOC, error) {
	// Auto-detect hash type (MD5, SHA1, SHA256)
	hashType := "hash"
	switch len(hash) {
	case 32:
		hashType = "md5"
	case 40:
		hashType = "sha1"
	case 64:
		hashType = "sha256"
	}

	return c.CheckIOC(ctx, hashType, hash)
}

// CheckIPAddress checks if an IP is associated with malicious activity
func (c *DarkAPIClient) CheckIPAddress(ctx context.Context, ip string) (*ThreatIOC, error) {
	return c.CheckIOC(ctx, "ip", ip)
}

// CheckDomain checks if a domain is malicious
func (c *DarkAPIClient) CheckDomain(ctx context.Context, domain string) (*ThreatIOC, error) {
	return c.CheckIOC(ctx, "domain", domain)
}
