# AfterSec Monetization & License Tiers

## Overview

AfterSec uses a three-tier licensing model that balances accessibility (free standalone use) with sustainable revenue from managed services and enterprise features.

## License Tiers

### 🆓 FREE Tier (Basic)
**Price:** $0
**Target:** Individual developers, hobbyists, security researchers

**Features:**
- ✅ Full EDR monitoring (Endpoint Security API)
- ✅ Local scanning & baseline/diff
- ✅ Starlark plugins + YARA rules
- ✅ GUI + CLI
- ✅ **BYOK AI** (Bring Your Own API Key)
  - Users provide their own OpenAI/Anthropic/Gemini keys
  - No AI budget limits from AfterSec
  - They pay API costs directly to providers
- ❌ No dark web intelligence
- ❌ No enterprise server
- ❌ No managed AI credits

**Value Proposition:** "Professional-grade EDR, completely free. Pay only for your own AI API usage."

---

### 💼 PRO Tier (Professional)
**Price:** $29/endpoint/month
**Target:** SMBs, security teams (10-100 endpoints)

**Features:**
- ✅ Everything in Free
- ✅ **$25/month Managed AI Credits**
  - ~25,000 Gemini queries/month included
  - Auto-selects cheapest model (Gemini 2.5 Flash)
  - No need to manage API keys
  - Usage dashboard with budget tracking
- ✅ **Dark Web Intelligence** (DarkAPI.io)
  - Credential breach monitoring (15B+ records)
  - Malware hash correlation
  - C2 server/IP detection
  - Weekly breach scans
- ✅ Enterprise server (self-hosted)
- ✅ Multi-endpoint dashboard
- ✅ Email alerts

**Cost Breakdown:**
- Revenue: $29/endpoint/month
- AI costs: ~$25/month (included credits)
- DarkAPI: $199/month ÷ 100 endpoints = $2/endpoint
- **Gross Margin:** ~$2/endpoint/month ($24/year)

**Value Proposition:** "10x cheaper than CrowdStrike's dark web add-on ($50-100/endpoint/year), with managed AI included."

---

### 🏢 ENTERPRISE Tier
**Price:** $79/endpoint/month
**Target:** Large enterprises (100+ endpoints)

**Features:**
- ✅ Everything in Pro
- ✅ **$75/month Premium AI - SWARM Mode**
  - Multi-LLM consensus (OpenAI + Anthropic + Gemini)
  - 3 models analyze each threat
  - Higher confidence scoring
  - ~7,500 SWARM queries/month
- ✅ **Advanced Dark Web Intelligence**
  - Daily credential scans (vs weekly)
  - Dark web forum monitoring
  - Custom keyword tracking
  - Real-time alerts (Slack/Teams/PagerDuty)
- ✅ SSO/SAML integration
- ✅ Compliance reporting (CIS, NIST, SOC2)
- ✅ Dedicated support
- ✅ SLA guarantees

**Cost Breakdown:**
- Revenue: $79/endpoint/month
- AI costs: ~$75/month (SWARM mode)
- DarkAPI: $199/month ÷ 1000+ endpoints = $0.20/endpoint
- **Gross Margin:** ~$4/endpoint/month ($48/year)

**Value Proposition:** "Enterprise EDR with multi-LLM AI for less than CrowdStrike Falcon Complete ($100-200/endpoint/month)."

---

## Technical Implementation

### 1. Server-Side Enforcement

#### Middleware (pkg/server/api/rest/middleware.go)

```go
// Protect dark web endpoints
mux.HandleFunc("/api/v1/darkweb/alerts",
    jwtManager.HTTPMiddleware(
        router.RequireTier(TierProfessional)(HandleDarkWebAlerts)))

// Protect SWARM mode
mux.HandleFunc("/api/v1/ai/swarm",
    jwtManager.HTTPMiddleware(
        router.RequireTier(TierEnterprise)(HandleSWARMAnalysis)))
```

#### Tier Requirements

```go
type TierRequirement string

const (
    TierBasic        TierRequirement = "basic"        // Free
    TierProfessional TierRequirement = "professional" // $29/mo
    TierEnterprise   TierRequirement = "enterprise"   // $79/mo
)
```

#### Response on Insufficient Tier

```json
{
  "error": "Insufficient license tier",
  "current_tier": "basic",
  "required_tier": "professional",
  "message": "Upgrade to Professional ($29/endpoint/month) to access dark web intelligence",
  "upgrade_url": "/api/v1/organizations/{id}/upgrade"
}
```

HTTP Status: `402 Payment Required`

### 2. AI Budget Allocation

#### Budget Limits by Tier

```go
func GetAIBudgetForTier(tier string) (dailyUSD, monthlyUSD float64) {
    switch tier {
    case "basic":
        return 0, 0  // BYOK - no limits
    case "professional":
        return 0.83, 25.0  // $25/month ÷ 30 days
    case "enterprise":
        return 2.50, 75.0  // $75/month ÷ 30 days
    }
}
```

#### Model Selection by Tier

```go
func GetRecommendedAIProvider(tier string) string {
    switch tier {
    case "basic":
        return ""  // User chooses (BYOK)
    case "professional":
        return "gemini"  // Auto-select cheapest
    case "enterprise":
        return "swarm"  // Multi-LLM consensus
    }
}
```

### 3. Dark Web Feature Gating

```go
func GetDarkWebFeaturesForTier(tier string) map[string]bool {
    features := map[string]bool{
        "credential_monitoring": false,
        "hash_correlation":      false,
        "network_ioc":           false,
        "dark_web_mentions":     false,
        "daily_scans":           false,
        "real_time_alerts":      false,
    }

    switch tier {
    case "professional":
        features["credential_monitoring"] = true
        features["hash_correlation"] = true
        features["network_ioc"] = true
        // Weekly scans only
    case "enterprise":
        // All features enabled
        for k := range features {
            features[k] = true
        }
    }

    return features
}
```

### 4. Client-Side Integration

```go
// Initialize tier manager
tierMgr := client.NewTierManager("professional", orgID)

// Check before making AI request
if err := tierMgr.CheckAIBudget(ctx); err != nil {
    // Budget exceeded - show upgrade prompt
    fmt.Println(tierMgr.GetUpgradeMessage("managed_ai"))
    return
}

// Check dark web access
if !tierMgr.CanUseDarkWebIntel() {
    fmt.Println(tierMgr.GetUpgradeMessage("dark_web"))
    return
}

// Record AI usage
tierMgr.RecordAIUsage("gemini-2.5-flash", tokensIn, tokensOut)
```

### 5. Dashboard Integration

```tsx
// Display tier status banner
<TierStatusBanner orgId={organizationId} />
```

Shows:
- Current tier badge (FREE/PRO/ENTERPRISE)
- AI budget usage bar
- BYOK indicator (for basic tier)
- SWARM mode indicator (for enterprise)
- Upgrade button with modal

---

## API Endpoints

### Get Tier Information
```http
GET /api/v1/organizations/tier?org_id={id}
Authorization: Bearer {jwt_token}
```

Response:
```json
{
  "current_tier": "professional",
  "tier_level": 2,
  "ai_budget": {
    "daily_limit_usd": 0.83,
    "monthly_limit_usd": 25.0,
    "daily_used_usd": 2.45,
    "monthly_used_usd": 12.30,
    "daily_remaining_usd": -1.62,
    "monthly_remaining_usd": 12.70,
    "percent_used": 49.2,
    "is_byok": false
  },
  "dark_web_features": {
    "credential_monitoring": true,
    "hash_correlation": true,
    "network_ioc": true,
    "dark_web_mentions": false,
    "daily_scans": false,
    "real_time_alerts": false
  },
  "max_ai_models": 1,
  "features": {
    "edr_monitoring": true,
    "managed_ai": true,
    "dark_web_intel": true,
    "swarm_mode": false,
    "sso": false
  },
  "upgrade_options": [
    {
      "target_tier": "enterprise",
      "price_per_month": 79.0,
      "description": "Upgrade to Enterprise for SWARM mode AI",
      "features": [
        "$75/month AI credits (SWARM mode)",
        "Multi-LLM consensus analysis",
        "Daily credential scans",
        "SSO/SAML integration"
      ]
    }
  ]
}
```

### Upgrade Tier
```http
POST /api/v1/organizations/upgrade
Authorization: Bearer {jwt_token}
Content-Type: application/json

{
  "organization_id": "org-123",
  "target_tier": "enterprise",
  "payment_method_id": "pm_stripe_123"
}
```

Response:
```json
{
  "success": true,
  "new_tier": "enterprise",
  "upgraded_at": "2026-03-25T10:30:00Z",
  "ai_budget": {
    "daily_usd": 2.50,
    "monthly_usd": 75.0
  },
  "message": "Successfully upgraded to enterprise tier"
}
```

### Get AI Budget Status
```http
GET /api/v1/ai/budget?org_id={id}
Authorization: Bearer {jwt_token}
```

### Get AI Usage Statistics
```http
GET /api/v1/ai/usage?org_id={id}
Authorization: Bearer {jwt_token}
```

---

## Revenue Projections

### Scenario 1: Small Adoption
- 500 Free users (GitHub stars, community)
- 50 Pro customers @ $29/mo = **$1,450/month**
- 5 Enterprise @ $79/mo = **$395/month**
- **Total: $1,845/month** ($22,140/year)

### Scenario 2: Medium Adoption
- 2,000 Free users
- 200 Pro customers @ $29/mo = **$5,800/month**
- 20 Enterprise @ $79/mo = **$1,580/month**
- **Total: $7,380/month** ($88,560/year)

### Scenario 3: Strong Adoption
- 10,000 Free users
- 500 Pro customers @ $29/mo = **$14,500/month**
- 50 Enterprise @ $79/mo = **$3,950/month**
- **Total: $18,450/month** ($221,400/year)

---

## Competitive Positioning

| Feature | AfterSec (Pro) | CrowdStrike | SentinelOne |
|---------|----------------|-------------|-------------|
| **Base EDR** | ✅ FREE | $100-150/endpoint | $100-150/endpoint |
| **Dark Web Intel** | ✅ $29 (included) | 💰 $50-100 extra | 💰 $50-100 extra |
| **AI Analysis** | ✅ $29 (included) | ⚠️ Single model | ⚠️ Single model |
| **SWARM Mode** | ✅ $79 | ❌ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ |

**Key Differentiators:**
1. **10x cheaper** than competitors for dark web intelligence
2. **Only EDR** with multi-LLM SWARM mode
3. **FREE tier** drives adoption and community
4. **BYOK option** removes vendor lock-in

---

## Implementation Checklist

### Phase 1: Foundation ✅
- [x] License tier database schema
- [x] Server-side middleware enforcement
- [x] AI budget allocation logic
- [x] Dark web feature gating
- [x] Tier management API endpoints
- [x] Dashboard tier status banner

### Phase 2: Payment Integration (Next)
- [ ] Stripe integration
  - [ ] Customer creation
  - [ ] Subscription management
  - [ ] Payment method handling
  - [ ] Webhook processing (subscription events)
- [ ] Invoice generation
- [ ] Usage metering
- [ ] Prorated upgrades/downgrades

### Phase 3: Advanced Features (Later)
- [ ] Self-service tier upgrades
- [ ] Trial periods (14-day Enterprise trial)
- [ ] Volume discounts (100+ endpoints)
- [ ] Annual billing (15% discount)
- [ ] Partner/reseller tiers
- [ ] Academic/non-profit pricing

---

## Usage Examples

### Client CLI
```bash
# Check current tier
aftersec tier status

# View AI budget
aftersec tier budget

# Attempt upgrade
aftersec tier upgrade --tier professional

# View available features
aftersec tier features
```

### Daemon Startup
```go
// Load configuration
cfg := client.LoadConfig()
org := fetchOrganization(cfg.Server.OrganizationID)

// Initialize tier manager
tierMgr := client.NewTierManager(org.LicenseTier, org.ID)

// Check features before enabling
if tierMgr.CanUseDarkWebIntel() {
    enableDarkWebMonitoring()
}

if tierMgr.CanUseSWARMMode() {
    enableMultiLLMAnalysis()
}
```

### AI Analysis
```go
// Check budget before analysis
if err := tierMgr.CheckAIBudget(ctx); err != nil {
    log.Printf("AI budget exceeded: %v", err)
    // Fall back to heuristic analysis
    return heuristicAnalysis(threat)
}

// Select provider based on tier
provider := tierMgr.GetRecommendedAIProvider()

// Perform analysis
result, tokens := analyzeWithAI(threat, provider)

// Record usage
tierMgr.RecordAIUsage(provider, tokens.Input, tokens.Output)
```

---

## Frequently Asked Questions

### Can I use AfterSec for free forever?
Yes! The basic tier is completely free for standalone use. You only pay if you want managed AI credits or dark web intelligence.

### What is BYOK (Bring Your Own Key)?
In the basic (free) tier, you provide your own API keys for OpenAI, Anthropic, or Google. You pay them directly for usage. AfterSec doesn't charge you for AI.

### How is the Professional tier different from CrowdStrike?
We're 10x cheaper ($29 vs $300+) and include dark web intelligence for FREE (CrowdStrike charges $50-100 extra). Plus, you get managed AI credits.

### What is SWARM mode?
SWARM mode (Enterprise tier only) queries 3 different AI models simultaneously and uses consensus voting for higher confidence threat analysis. No other EDR has this.

### Can I self-host the server?
Yes! All tiers can self-host the enterprise server. You're only paying for managed services (AI credits, dark web API access).

### What happens if I exceed my AI budget?
We'll notify you and offer to upgrade. Your service continues, but AI analysis will be throttled until next month or you upgrade.

---

## Support

For questions about licensing or billing:
- Email: sales@aftersec.io
- Documentation: https://docs.aftersec.io/pricing
- Upgrade: https://dashboard.aftersec.io/upgrade
