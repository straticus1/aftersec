package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// TierManager handles license tier enforcement on the client side
type TierManager struct {
	mu              sync.RWMutex
	currentTier     string
	organizationID  string
	budgetTracker   *BudgetTracker
	serverConfigured bool
}

// BudgetTracker is a simple budget tracker (avoiding import cycle with pkg/ai)
type BudgetTracker struct {
	dailyLimit   float64
	monthlyLimit float64
	dailyUsed    float64
	monthlyUsed  float64
}

// NewTierManager creates a new tier manager
func NewTierManager(tier string, orgID string) *TierManager {
	dailyBudget, monthlyBudget := GetAIBudgetForTier(tier)

	var tracker *BudgetTracker
	if dailyBudget > 0 || monthlyBudget > 0 {
		tracker = &BudgetTracker{
			dailyLimit:   dailyBudget,
			monthlyLimit: monthlyBudget,
		}
	}

	return &TierManager{
		currentTier:     tier,
		organizationID:  orgID,
		budgetTracker:   tracker,
		serverConfigured: orgID != "",
	}
}

// GetAIBudgetForTier returns daily and monthly AI budget limits based on tier
func GetAIBudgetForTier(tier string) (dailyUSD float64, monthlyUSD float64) {
	switch strings.ToLower(tier) {
	case "basic":
		// BYOK - no managed AI budget
		return 0, 0
	case "professional":
		// $25/month included
		return 0.83, 25.0
	case "enterprise":
		// $75/month included for SWARM mode
		return 2.50, 75.0
	default:
		return 0, 0
	}
}

// CheckAIBudget checks if AI budget allows a request
func (tm *TierManager) CheckAIBudget(ctx context.Context) error {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Basic tier is BYOK - no budget limits from AfterSec
	if tm.currentTier == "basic" {
		return nil
	}

	// If no budget tracker (shouldn't happen for paid tiers)
	if tm.budgetTracker == nil {
		return fmt.Errorf("no budget tracker configured for tier %s", tm.currentTier)
	}

	// Simple budget check
	if tm.budgetTracker.dailyUsed >= tm.budgetTracker.dailyLimit {
		return fmt.Errorf("daily budget limit exceeded")
	}
	if tm.budgetTracker.monthlyUsed >= tm.budgetTracker.monthlyLimit {
		return fmt.Errorf("monthly budget limit exceeded")
	}

	return nil
}

// RecordAIUsage records AI API usage
func (tm *TierManager) RecordAIUsage(model string, tokensIn, tokensOut int64) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Basic tier is BYOK - don't track
	if tm.currentTier == "basic" {
		return nil
	}

	if tm.budgetTracker == nil {
		return nil
	}

	// Simple cost calculation (can be enhanced later)
	// Average: $0.0001 per query
	cost := 0.0001
	tm.budgetTracker.dailyUsed += cost
	tm.budgetTracker.monthlyUsed += cost

	return nil
}

// GetBudgetStats returns current budget statistics
func (tm *TierManager) GetBudgetStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if tm.budgetTracker == nil {
		return map[string]interface{}{
			"tier":   tm.currentTier,
			"is_byok": true,
			"message": "Bring Your Own API Key - no budget limits",
		}
	}

	return map[string]interface{}{
		"tier":            tm.currentTier,
		"is_byok":         false,
		"daily_limit":     tm.budgetTracker.dailyLimit,
		"daily_used":      tm.budgetTracker.dailyUsed,
		"monthly_limit":   tm.budgetTracker.monthlyLimit,
		"monthly_used":    tm.budgetTracker.monthlyUsed,
	}
}

// CanUseDarkWebIntel checks if dark web intelligence is available
func (tm *TierManager) CanUseDarkWebIntel() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return tm.currentTier == "professional" || tm.currentTier == "enterprise"
}

// CanUseSWARMMode checks if SWARM mode (multi-LLM) is available
func (tm *TierManager) CanUseSWARMMode() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return tm.currentTier == "enterprise"
}

// GetMaxAIModels returns how many AI models can be used simultaneously
func (tm *TierManager) GetMaxAIModels() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	switch strings.ToLower(tm.currentTier) {
	case "basic":
		return 1 // BYOK - single model
	case "professional":
		return 1 // Single model (auto-select cheapest: Gemini)
	case "enterprise":
		return 3 // SWARM mode - all models for consensus
	default:
		return 0
	}
}

// GetRecommendedAIProvider returns the best AI provider for the tier
func (tm *TierManager) GetRecommendedAIProvider() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	switch strings.ToLower(tm.currentTier) {
	case "basic":
		// BYOK - user chooses
		return ""
	case "professional":
		// Auto-select cheapest: Gemini
		return "gemini"
	case "enterprise":
		// SWARM mode uses all
		return "swarm"
	default:
		return ""
	}
}

// GetDarkWebFeatures returns enabled dark web features
func (tm *TierManager) GetDarkWebFeatures() map[string]bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	features := map[string]bool{
		"credential_monitoring": false,
		"hash_correlation":      false,
		"network_ioc":           false,
		"dark_web_mentions":     false,
		"daily_scans":           false,
		"real_time_alerts":      false,
	}

	switch strings.ToLower(tm.currentTier) {
	case "professional":
		features["credential_monitoring"] = true
		features["hash_correlation"] = true
		features["network_ioc"] = true
		// Weekly scans only
	case "enterprise":
		features["credential_monitoring"] = true
		features["hash_correlation"] = true
		features["network_ioc"] = true
		features["dark_web_mentions"] = true
		features["daily_scans"] = true
		features["real_time_alerts"] = true
	}

	return features
}

// UpgradeTier updates the tier (call after successful server upgrade)
func (tm *TierManager) UpgradeTier(newTier string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if newTier == tm.currentTier {
		return fmt.Errorf("already on tier: %s", newTier)
	}

	// Update tier
	tm.currentTier = newTier

	// Reinitialize budget tracker with new limits
	dailyBudget, monthlyBudget := GetAIBudgetForTier(newTier)
	if dailyBudget > 0 || monthlyBudget > 0 {
		tm.budgetTracker = &BudgetTracker{
			dailyLimit:   dailyBudget,
			monthlyLimit: monthlyBudget,
		}
	} else {
		tm.budgetTracker = nil // BYOK mode
	}

	return nil
}

// GetTierInfo returns tier information for display
func (tm *TierManager) GetTierInfo() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	dailyBudget, monthlyBudget := GetAIBudgetForTier(tm.currentTier)

	info := map[string]interface{}{
		"tier":             tm.currentTier,
		"organization_id":  tm.organizationID,
		"daily_budget_usd": dailyBudget,
		"monthly_budget_usd": monthlyBudget,
		"is_byok":          tm.currentTier == "basic",
		"max_ai_models":    tm.GetMaxAIModels(),
		"dark_web_enabled": tm.CanUseDarkWebIntel(),
		"swarm_mode":       tm.CanUseSWARMMode(),
	}

	return info
}

// ValidateFeatureAccess returns an error if feature is not available in current tier
func (tm *TierManager) ValidateFeatureAccess(feature string) error {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	switch feature {
	case "dark_web":
		if !tm.CanUseDarkWebIntel() {
			return fmt.Errorf("dark web intelligence requires Professional tier or higher (current: %s)", tm.currentTier)
		}
	case "swarm_mode":
		if !tm.CanUseSWARMMode() {
			return fmt.Errorf("SWARM mode requires Enterprise tier (current: %s)", tm.currentTier)
		}
	case "managed_ai":
		if tm.currentTier == "basic" {
			return fmt.Errorf("managed AI requires Professional tier or higher (current: %s)", tm.currentTier)
		}
	default:
		// Unknown feature - allow by default
		return nil
	}

	return nil
}

// GetUpgradeMessage returns a user-friendly upgrade message
func (tm *TierManager) GetUpgradeMessage(feature string) string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	switch feature {
	case "dark_web":
		return fmt.Sprintf("🔒 Dark web intelligence requires Professional tier ($29/endpoint/month)\n"+
			"   Current tier: %s\n"+
			"   Upgrade to access:\n"+
			"   • Credential breach monitoring (15B+ records)\n"+
			"   • Malware hash correlation\n"+
			"   • C2 server detection\n"+
			"   • $25/month AI credits included", tm.currentTier)
	case "swarm_mode":
		return fmt.Sprintf("🔒 SWARM mode requires Enterprise tier ($79/endpoint/month)\n"+
			"   Current tier: %s\n"+
			"   Upgrade to access:\n"+
			"   • Multi-LLM consensus (3 models)\n"+
			"   • Higher confidence analysis\n"+
			"   • Advanced dark web monitoring\n"+
			"   • $75/month AI credits included", tm.currentTier)
	case "managed_ai":
		return fmt.Sprintf("🔒 Managed AI requires Professional tier or higher\n"+
			"   Current tier: %s (BYOK - Bring Your Own API Key)\n"+
			"   Upgrade to Professional ($29/endpoint/month):\n"+
			"   • $25/month AI credits included\n"+
			"   • No need to manage API keys\n"+
			"   • Optimized model selection", tm.currentTier)
	default:
		return fmt.Sprintf("This feature requires a higher tier (current: %s)", tm.currentTier)
	}
}
