package ai

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BudgetTracker tracks LLM API usage and enforces budget limits
type BudgetTracker struct {
	mu sync.RWMutex

	// Budget limits
	dailyLimit   float64 // Daily budget limit in USD
	monthlyLimit float64 // Monthly budget limit in USD

	// Current usage
	dailySpend   float64 // Current daily spend in USD
	monthlySpend float64 // Current monthly spend in USD
	lastReset    time.Time
	monthStart   time.Time

	// Per-model tracking
	modelCosts map[string]*ModelCost
}

// ModelCost tracks usage for a specific model
type ModelCost struct {
	RequestCount int64
	TokensIn     int64
	TokensOut    int64
	TotalCost    float64
}

// Model pricing (per 1M tokens)
var modelPricing = map[string]struct {
	InputCostPerM  float64
	OutputCostPerM float64
}{
	"gpt-4o-mini":               {InputCostPerM: 0.15, OutputCostPerM: 0.60},
	"claude-3-5-sonnet-latest":  {InputCostPerM: 3.00, OutputCostPerM: 15.00},
	"gemini-2.5-flash":          {InputCostPerM: 0.075, OutputCostPerM: 0.30},
}

// NewBudgetTracker creates a new budget tracker with daily and monthly limits
func NewBudgetTracker(dailyLimit, monthlyLimit float64) *BudgetTracker {
	now := time.Now()
	return &BudgetTracker{
		dailyLimit:   dailyLimit,
		monthlyLimit: monthlyLimit,
		dailySpend:   0,
		monthlySpend: 0,
		lastReset:    now,
		monthStart:   time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()),
		modelCosts:   make(map[string]*ModelCost),
	}
}

// CheckBudget returns an error if budget is exceeded
func (bt *BudgetTracker) CheckBudget(ctx context.Context) error {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	bt.resetIfNeeded()

	if bt.dailySpend >= bt.dailyLimit {
		return fmt.Errorf("daily budget limit exceeded: $%.2f / $%.2f", bt.dailySpend, bt.dailyLimit)
	}

	if bt.monthlySpend >= bt.monthlyLimit {
		return fmt.Errorf("monthly budget limit exceeded: $%.2f / $%.2f", bt.monthlySpend, bt.monthlyLimit)
	}

	return nil
}

// RecordUsage records API usage and calculates cost
func (bt *BudgetTracker) RecordUsage(model string, tokensIn, tokensOut int64) error {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	bt.resetIfNeeded()

	pricing, ok := modelPricing[model]
	if !ok {
		// Default to most expensive model if unknown
		pricing = modelPricing["claude-3-5-sonnet-latest"]
	}

	// Calculate cost
	inputCost := float64(tokensIn) / 1_000_000 * pricing.InputCostPerM
	outputCost := float64(tokensOut) / 1_000_000 * pricing.OutputCostPerM
	totalCost := inputCost + outputCost

	// Update totals
	bt.dailySpend += totalCost
	bt.monthlySpend += totalCost

	// Update per-model tracking
	if bt.modelCosts[model] == nil {
		bt.modelCosts[model] = &ModelCost{}
	}
	bt.modelCosts[model].RequestCount++
	bt.modelCosts[model].TokensIn += tokensIn
	bt.modelCosts[model].TokensOut += tokensOut
	bt.modelCosts[model].TotalCost += totalCost

	return nil
}

// GetStats returns current budget statistics
func (bt *BudgetTracker) GetStats() map[string]interface{} {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	bt.resetIfNeeded()

	stats := map[string]interface{}{
		"daily_limit":        bt.dailyLimit,
		"daily_spend":        bt.dailySpend,
		"daily_remaining":    bt.dailyLimit - bt.dailySpend,
		"daily_percent_used": (bt.dailySpend / bt.dailyLimit) * 100,
		"monthly_limit":      bt.monthlyLimit,
		"monthly_spend":      bt.monthlySpend,
		"monthly_remaining":  bt.monthlyLimit - bt.monthlySpend,
		"monthly_percent_used": (bt.monthlySpend / bt.monthlyLimit) * 100,
		"last_reset":         bt.lastReset,
		"month_start":        bt.monthStart,
	}

	// Add per-model stats
	modelStats := make(map[string]interface{})
	for model, cost := range bt.modelCosts {
		modelStats[model] = map[string]interface{}{
			"requests":   cost.RequestCount,
			"tokens_in":  cost.TokensIn,
			"tokens_out": cost.TokensOut,
			"total_cost": cost.TotalCost,
		}
	}
	stats["models"] = modelStats

	return stats
}

// resetIfNeeded resets daily/monthly counters if needed
func (bt *BudgetTracker) resetIfNeeded() {
	now := time.Now()

	// Reset daily counter if day has changed
	if now.Sub(bt.lastReset) >= 24*time.Hour {
		bt.dailySpend = 0
		bt.lastReset = now
		// Reset per-model daily stats
		for model := range bt.modelCosts {
			bt.modelCosts[model] = &ModelCost{}
		}
	}

	// Reset monthly counter if month has changed
	if now.Month() != bt.monthStart.Month() || now.Year() != bt.monthStart.Year() {
		bt.monthlySpend = 0
		bt.monthStart = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	}
}

// Global budget tracker instance
var globalBudget *BudgetTracker
var budgetMu sync.RWMutex

// InitBudgetTracker initializes the global budget tracker
func InitBudgetTracker(dailyLimit, monthlyLimit float64) {
	budgetMu.Lock()
	defer budgetMu.Unlock()

	globalBudget = NewBudgetTracker(dailyLimit, monthlyLimit)
}

// GetBudgetTracker returns the global budget tracker
func GetBudgetTracker() *BudgetTracker {
	budgetMu.RLock()
	defer budgetMu.RUnlock()

	return globalBudget
}

// CircuitBreaker implements circuit breaker pattern for LLM API calls
type CircuitBreaker struct {
	mu sync.RWMutex

	name           string
	maxFailures    int
	resetTimeout   time.Duration
	state          CircuitState
	failures       int
	lastFailTime   time.Time
	consecutiveFail int
}

// CircuitState represents the state of the circuit breaker
type CircuitState string

const (
	StateClosed   CircuitState = "closed"   // Normal operation
	StateOpen     CircuitState = "open"     // Failing, rejecting requests
	StateHalfOpen CircuitState = "half-open" // Testing if service recovered
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        StateClosed,
		failures:     0,
	}
}

// Call executes the function if the circuit is closed or half-open
func (cb *CircuitBreaker) Call(ctx context.Context, fn func() error) error {
	cb.mu.Lock()

	// Check if we should transition from open to half-open
	if cb.state == StateOpen && time.Since(cb.lastFailTime) >= cb.resetTimeout {
		cb.state = StateHalfOpen
		cb.failures = 0
	}

	// Reject if circuit is open
	if cb.state == StateOpen {
		cb.mu.Unlock()
		return fmt.Errorf("circuit breaker %s is open (too many failures)", cb.name)
	}

	cb.mu.Unlock()

	// Execute the function
	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailTime = time.Now()
		cb.consecutiveFail++

		// Open circuit if max failures reached
		if cb.failures >= cb.maxFailures {
			cb.state = StateOpen
			return fmt.Errorf("circuit breaker %s opened after %d failures: %w", cb.name, cb.failures, err)
		}

		if cb.state == StateHalfOpen {
			// Failed in half-open state, go back to open
			cb.state = StateOpen
		}

		return err
	}

	// Success - reset consecutive failures and close circuit
	cb.consecutiveFail = 0
	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.failures = 0
	}

	return nil
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return map[string]interface{}{
		"name":              cb.name,
		"state":             string(cb.state),
		"failures":          cb.failures,
		"consecutive_fail":  cb.consecutiveFail,
		"max_failures":      cb.maxFailures,
		"last_fail_time":    cb.lastFailTime,
		"reset_timeout_sec": cb.resetTimeout.Seconds(),
	}
}

// Global circuit breakers for each LLM provider
var (
	openAICircuitBreaker    *CircuitBreaker
	anthropicCircuitBreaker *CircuitBreaker
	geminiCircuitBreaker    *CircuitBreaker
	circuitBreakersOnce     sync.Once
)

// InitCircuitBreakers initializes circuit breakers for all LLM providers
func InitCircuitBreakers() {
	circuitBreakersOnce.Do(func() {
		openAICircuitBreaker = NewCircuitBreaker("openai", 5, 30*time.Second)
		anthropicCircuitBreaker = NewCircuitBreaker("anthropic", 5, 30*time.Second)
		geminiCircuitBreaker = NewCircuitBreaker("gemini", 5, 30*time.Second)
	})
}

// GetCircuitBreaker returns the circuit breaker for a specific provider
func GetCircuitBreaker(provider string) *CircuitBreaker {
	InitCircuitBreakers()

	switch provider {
	case "openai":
		return openAICircuitBreaker
	case "anthropic":
		return anthropicCircuitBreaker
	case "gemini":
		return geminiCircuitBreaker
	default:
		// Return a generic circuit breaker for unknown providers
		return NewCircuitBreaker(provider, 5, 30*time.Second)
	}
}
