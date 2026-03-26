package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"aftersec/pkg/server/repository"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	orgContextKey contextKey = "organization"
)

// TierRequirement defines the minimum tier needed
type TierRequirement string

const (
	TierBasic        TierRequirement = "basic"
	TierProfessional TierRequirement = "professional"
	TierEnterprise   TierRequirement = "enterprise"
)

// tierHierarchy defines the tier levels (higher number = higher tier)
var tierHierarchy = map[string]int{
	"basic":        1,
	"professional": 2,
	"enterprise":   3,
}

// RequireTier creates a middleware that enforces minimum license tier
func (rt *Router) RequireTier(minTier TierRequirement) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Extract organization ID from query params or request body
			orgID := rt.getOrgIDFromRequest(r)
			if orgID == "" {
				http.Error(w, "Missing organization ID", http.StatusBadRequest)
				return
			}

			// Fetch organization
			org, err := rt.repos.Organizations.GetByID(r.Context(), orgID)
			if err != nil {
				http.Error(w, "Failed to fetch organization", http.StatusInternalServerError)
				return
			}
			if org == nil {
				http.Error(w, "Organization not found", http.StatusNotFound)
				return
			}

			// Check tier requirement
			if !hasRequiredTier(org.LicenseTier, string(minTier)) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired) // 402
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":        "Insufficient license tier",
					"current_tier": org.LicenseTier,
					"required_tier": minTier,
					"message":      getTierUpgradeMessage(minTier),
					"upgrade_url":  "/api/v1/organizations/" + orgID + "/upgrade",
				})
				return
			}

			// Add organization to context for downstream handlers
			ctx := context.WithValue(r.Context(), orgContextKey, org)
			next(w, r.WithContext(ctx))
		}
	}
}

// hasRequiredTier checks if currentTier meets the minimum requirement
func hasRequiredTier(currentTier, requiredTier string) bool {
	currentLevel, ok := tierHierarchy[strings.ToLower(currentTier)]
	if !ok {
		return false // Unknown tier defaults to no access
	}

	requiredLevel, ok := tierHierarchy[strings.ToLower(requiredTier)]
	if !ok {
		return false
	}

	return currentLevel >= requiredLevel
}

// getTierUpgradeMessage returns a user-friendly upgrade message
func getTierUpgradeMessage(tier TierRequirement) string {
	switch tier {
	case TierProfessional:
		return "Upgrade to Professional ($29/endpoint/month) to access dark web intelligence, managed AI credits, and multi-endpoint dashboard"
	case TierEnterprise:
		return "Upgrade to Enterprise ($79/endpoint/month) to access SWARM mode AI, advanced dark web monitoring, SSO, and compliance reporting"
	default:
		return "Upgrade your license tier to access this feature"
	}
}

// getOrgIDFromRequest extracts organization ID from various request sources
func (rt *Router) getOrgIDFromRequest(r *http.Request) string {
	// Try query parameter first
	orgID := r.URL.Query().Get("org_id")
	if orgID != "" {
		return orgID
	}

	// Try organization_id parameter
	orgID = r.URL.Query().Get("organization_id")
	if orgID != "" {
		return orgID
	}

	// Try path parameter (e.g., /api/v1/organizations/{id})
	if strings.HasPrefix(r.URL.Path, "/api/v1/organizations/") {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 5 {
			return parts[4]
		}
	}

	// Could also parse from JWT claims if organization is embedded in token
	// For now, return empty string
	return ""
}

// GetOrganizationFromContext retrieves the organization from request context
func GetOrganizationFromContext(ctx context.Context) *repository.Organization {
	org, ok := ctx.Value(orgContextKey).(*repository.Organization)
	if !ok {
		return nil
	}
	return org
}

// GetAIBudgetForTier returns daily and monthly AI budget limits based on tier
func GetAIBudgetForTier(tier string) (dailyUSD float64, monthlyUSD float64) {
	switch strings.ToLower(tier) {
	case "basic":
		// BYOK - no managed AI budget
		return 0, 0
	case "professional":
		// $25/month included = ~833 Gemini requests/day
		// Daily: $25 / 30 days = $0.83/day
		// Using Gemini 2.5 Flash: $0.075 per 1M input + $0.30 per 1M output
		// Average query: ~500 input tokens, ~200 output tokens
		// Cost per query: (500/1M * 0.075) + (200/1M * 0.30) = $0.0000975 (~$0.0001)
		// $0.83/day = ~8,300 queries/day (very generous)
		return 0.83, 25.0
	case "enterprise":
		// $75/month included for SWARM mode (3 models)
		// Daily: $75 / 30 = $2.50/day
		// SWARM mode uses 3x queries, so effective: ~2,500 queries/day
		return 2.50, 75.0
	default:
		return 0, 0
	}
}

// GetMaxAIModelsForTier returns how many AI models can be used simultaneously
func GetMaxAIModelsForTier(tier string) int {
	switch strings.ToLower(tier) {
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

// GetDarkWebFeaturesForTier returns enabled dark web features by tier
func GetDarkWebFeaturesForTier(tier string) map[string]bool {
	features := map[string]bool{
		"credential_monitoring": false,
		"hash_correlation":      false,
		"network_ioc":           false,
		"dark_web_mentions":     false,
		"daily_scans":           false,
		"real_time_alerts":      false,
	}

	switch strings.ToLower(tier) {
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
