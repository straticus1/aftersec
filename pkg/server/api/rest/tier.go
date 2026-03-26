package rest

import (
	"encoding/json"
	"net/http"
	"time"
)

// TierInfo represents the license tier information and capabilities
type TierInfo struct {
	CurrentTier     string                 `json:"current_tier"`
	TierLevel       int                    `json:"tier_level"`
	AIBudget        AIBudgetInfo           `json:"ai_budget"`
	DarkWebFeatures map[string]bool        `json:"dark_web_features"`
	MaxAIModels     int                    `json:"max_ai_models"`
	Features        map[string]interface{} `json:"features"`
	UpgradeOptions  []UpgradeOption        `json:"upgrade_options"`
}

// AIBudgetInfo contains AI budget limits and usage
type AIBudgetInfo struct {
	DailyLimitUSD    float64 `json:"daily_limit_usd"`
	MonthlyLimitUSD  float64 `json:"monthly_limit_usd"`
	DailyUsedUSD     float64 `json:"daily_used_usd"`
	MonthlyUsedUSD   float64 `json:"monthly_used_usd"`
	DailyRemainingUSD float64 `json:"daily_remaining_usd"`
	MonthlyRemainingUSD float64 `json:"monthly_remaining_usd"`
	PercentUsed      float64 `json:"percent_used"`
	IsBYOK           bool    `json:"is_byok"` // Bring Your Own Key (basic tier)
}

// UpgradeOption represents an available tier upgrade
type UpgradeOption struct {
	TargetTier    string  `json:"target_tier"`
	PricePerMonth float64 `json:"price_per_month"`
	Description   string  `json:"description"`
	Features      []string `json:"features"`
}

// UpgradeTierRequest is the request body for tier upgrades
type UpgradeTierRequest struct {
	OrganizationID string `json:"organization_id"`
	TargetTier     string `json:"target_tier"`
	PaymentMethodID string `json:"payment_method_id"` // Stripe payment method ID
}

// handleGetTierInfo returns current tier information and capabilities
func (rt *Router) handleGetTierInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := rt.getOrgIDFromRequest(r)
	if orgID == "" {
		http.Error(w, "Missing organization ID", http.StatusBadRequest)
		return
	}

	org, err := rt.repos.Organizations.GetByID(r.Context(), orgID)
	if err != nil {
		http.Error(w, "Failed to fetch organization", http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "Organization not found", http.StatusNotFound)
		return
	}

	// Get tier information
	dailyBudget, monthlyBudget := GetAIBudgetForTier(org.LicenseTier)
	maxModels := GetMaxAIModelsForTier(org.LicenseTier)
	darkWebFeatures := GetDarkWebFeaturesForTier(org.LicenseTier)

	// TODO: Fetch actual usage from budget tracker
	// For now, return zero usage
	tierInfo := TierInfo{
		CurrentTier: org.LicenseTier,
		TierLevel:   tierHierarchy[org.LicenseTier],
		AIBudget: AIBudgetInfo{
			DailyLimitUSD:   dailyBudget,
			MonthlyLimitUSD: monthlyBudget,
			DailyUsedUSD:    0,
			MonthlyUsedUSD:  0,
			DailyRemainingUSD: dailyBudget,
			MonthlyRemainingUSD: monthlyBudget,
			PercentUsed:     0,
			IsBYOK:          org.LicenseTier == "basic",
		},
		DarkWebFeatures: darkWebFeatures,
		MaxAIModels:     maxModels,
		Features:        getTierFeatures(org.LicenseTier),
		UpgradeOptions:  getUpgradeOptions(org.LicenseTier),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tierInfo)
}

// handleUpgradeTier processes a tier upgrade request
func (rt *Router) handleUpgradeTier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpgradeTierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.OrganizationID == "" || req.TargetTier == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate target tier
	if _, ok := tierHierarchy[req.TargetTier]; !ok {
		http.Error(w, "Invalid target tier", http.StatusBadRequest)
		return
	}

	// Fetch organization
	org, err := rt.repos.Organizations.GetByID(r.Context(), req.OrganizationID)
	if err != nil {
		http.Error(w, "Failed to fetch organization", http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "Organization not found", http.StatusNotFound)
		return
	}

	// Check if upgrade is valid (can't downgrade through this endpoint)
	currentLevel := tierHierarchy[org.LicenseTier]
	targetLevel := tierHierarchy[req.TargetTier]
	if targetLevel <= currentLevel {
		http.Error(w, "Cannot downgrade or upgrade to same tier", http.StatusBadRequest)
		return
	}

	// TODO: Process payment through Stripe
	// For now, just update the tier directly
	org.LicenseTier = req.TargetTier
	if err := rt.repos.Organizations.Update(r.Context(), org); err != nil {
		http.Error(w, "Failed to update organization tier", http.StatusInternalServerError)
		return
	}

	// Return updated tier info
	dailyBudget, monthlyBudget := GetAIBudgetForTier(org.LicenseTier)

	response := map[string]interface{}{
		"success":       true,
		"new_tier":      org.LicenseTier,
		"upgraded_at":   time.Now().Format(time.RFC3339),
		"ai_budget": map[string]float64{
			"daily_usd":   dailyBudget,
			"monthly_usd": monthlyBudget,
		},
		"message": "Successfully upgraded to " + org.LicenseTier + " tier",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleAIBudget returns current AI budget usage
func (rt *Router) handleAIBudget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := rt.getOrgIDFromRequest(r)
	if orgID == "" {
		http.Error(w, "Missing organization ID", http.StatusBadRequest)
		return
	}

	org, err := rt.repos.Organizations.GetByID(r.Context(), orgID)
	if err != nil {
		http.Error(w, "Failed to fetch organization", http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "Organization not found", http.StatusNotFound)
		return
	}

	dailyBudget, monthlyBudget := GetAIBudgetForTier(org.LicenseTier)

	// TODO: Integrate with actual BudgetTracker
	// For now, return mock data
	budgetInfo := AIBudgetInfo{
		DailyLimitUSD:   dailyBudget,
		MonthlyLimitUSD: monthlyBudget,
		DailyUsedUSD:    0,
		MonthlyUsedUSD:  0,
		DailyRemainingUSD: dailyBudget,
		MonthlyRemainingUSD: monthlyBudget,
		PercentUsed:     0,
		IsBYOK:          org.LicenseTier == "basic",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(budgetInfo)
}

// handleAIUsage returns detailed AI usage statistics
func (rt *Router) handleAIUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Return detailed usage stats from BudgetTracker
	// Including per-model breakdown, request counts, token usage

	usageStats := map[string]interface{}{
		"total_requests": 0,
		"total_cost_usd": 0,
		"models": map[string]interface{}{
			"gemini-2.5-flash": map[string]interface{}{
				"requests":   0,
				"tokens_in":  0,
				"tokens_out": 0,
				"cost_usd":   0,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usageStats)
}

// getTierFeatures returns a map of features enabled for a tier
func getTierFeatures(tier string) map[string]interface{} {
	features := map[string]interface{}{
		"edr_monitoring":       true,
		"starlark_plugins":     true,
		"yara_rules":          true,
		"local_scanning":      true,
		"gui_cli":             true,
		"managed_ai":          false,
		"dark_web_intel":      false,
		"enterprise_server":   false,
		"dashboard":           false,
		"swarm_mode":          false,
		"sso":                 false,
		"compliance_reports":  false,
	}

	switch tier {
	case "professional":
		features["managed_ai"] = true
		features["dark_web_intel"] = true
		features["enterprise_server"] = true
		features["dashboard"] = true
	case "enterprise":
		features["managed_ai"] = true
		features["dark_web_intel"] = true
		features["enterprise_server"] = true
		features["dashboard"] = true
		features["swarm_mode"] = true
		features["sso"] = true
		features["compliance_reports"] = true
	}

	return features
}

// getUpgradeOptions returns available upgrade options
func getUpgradeOptions(currentTier string) []UpgradeOption {
	options := []UpgradeOption{}

	switch currentTier {
	case "basic":
		options = append(options, UpgradeOption{
			TargetTier:    "professional",
			PricePerMonth: 29.0,
			Description:   "Upgrade to Professional for managed AI and dark web intelligence",
			Features: []string{
				"$25/month AI credits included",
				"Dark web credential monitoring",
				"IOC correlation (hashes, IPs, domains)",
				"Enterprise server with dashboard",
				"Email alerts",
			},
		})
		options = append(options, UpgradeOption{
			TargetTier:    "enterprise",
			PricePerMonth: 79.0,
			Description:   "Upgrade to Enterprise for SWARM mode AI and advanced features",
			Features: []string{
				"$75/month AI credits (SWARM mode)",
				"Multi-LLM consensus analysis",
				"Advanced dark web monitoring",
				"Daily credential scans",
				"SSO/SAML integration",
				"Compliance reporting",
				"Dedicated support",
			},
		})
	case "professional":
		options = append(options, UpgradeOption{
			TargetTier:    "enterprise",
			PricePerMonth: 79.0,
			Description:   "Upgrade to Enterprise for SWARM mode AI and advanced features",
			Features: []string{
				"$75/month AI credits (SWARM mode)",
				"Multi-LLM consensus analysis",
				"Advanced dark web monitoring",
				"Daily credential scans",
				"SSO/SAML integration",
				"Compliance reporting",
				"Dedicated support",
			},
		})
	}

	return options
}
