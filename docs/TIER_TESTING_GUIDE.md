# License Tier Testing Guide

Quick reference for testing the tier enforcement system.

## Database Setup

```sql
-- Create test organizations with different tiers

-- Basic tier (free)
INSERT INTO organizations (id, name, slug, license_tier)
VALUES ('org-basic-001', 'Free Tier Test', 'free-test', 'basic');

-- Professional tier
INSERT INTO organizations (id, name, slug, license_tier)
VALUES ('org-pro-001', 'Pro Tier Test', 'pro-test', 'professional');

-- Enterprise tier
INSERT INTO organizations (id, name, slug, license_tier)
VALUES ('org-ent-001', 'Enterprise Test', 'ent-test', 'enterprise');
```

## API Testing

### Test Tier Information Endpoint

```bash
# Get tier info for basic tier
curl -X GET "http://localhost:8080/api/v1/organizations/tier?org_id=org-basic-001" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response:
# {
#   "current_tier": "basic",
#   "ai_budget": {
#     "is_byok": true,
#     "daily_limit_usd": 0,
#     "monthly_limit_usd": 0
#   },
#   "max_ai_models": 1,
#   "dark_web_features": {
#     "credential_monitoring": false,
#     "hash_correlation": false,
#     ...
#   }
# }
```

### Test Dark Web Access (Should Fail for Basic)

```bash
# Try to access dark web alerts with basic tier
curl -X GET "http://localhost:8080/api/v1/darkweb/alerts?org_id=org-basic-001" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response: 402 Payment Required
# {
#   "error": "Insufficient license tier",
#   "current_tier": "basic",
#   "required_tier": "professional",
#   "message": "Upgrade to Professional ($29/endpoint/month)...",
#   "upgrade_url": "/api/v1/organizations/org-basic-001/upgrade"
# }
```

### Test Dark Web Access (Should Succeed for Pro)

```bash
# Access dark web alerts with professional tier
curl -X GET "http://localhost:8080/api/v1/darkweb/alerts?org_id=org-pro-001" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response: 200 OK with alerts data
```

### Test Tier Upgrade

```bash
# Upgrade from basic to professional
curl -X POST "http://localhost:8080/api/v1/organizations/upgrade" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "org-basic-001",
    "target_tier": "professional",
    "payment_method_id": "mock_payment_method"
  }'

# Expected response:
# {
#   "success": true,
#   "new_tier": "professional",
#   "ai_budget": {
#     "daily_usd": 0.83,
#     "monthly_usd": 25.0
#   }
# }
```

## Client-Side Testing

### Test Tier Manager

```go
package main

import (
    "context"
    "fmt"
    "aftersec/pkg/client"
)

func main() {
    // Test basic tier
    basicMgr := client.NewTierManager("basic", "org-basic-001")

    fmt.Println("Basic Tier Info:")
    fmt.Println(basicMgr.GetTierInfo())
    fmt.Println("Can use dark web?", basicMgr.CanUseDarkWebIntel())
    fmt.Println("Can use SWARM?", basicMgr.CanUseSWARMMode())

    // Test professional tier
    proMgr := client.NewTierManager("professional", "org-pro-001")

    fmt.Println("\nProfessional Tier Info:")
    fmt.Println(proMgr.GetTierInfo())
    fmt.Println("Can use dark web?", proMgr.CanUseDarkWebIntel())
    fmt.Println("Can use SWARM?", proMgr.CanUseSWARMMode())

    // Test AI budget checking
    ctx := context.Background()
    if err := proMgr.CheckAIBudget(ctx); err != nil {
        fmt.Println("Budget check failed:", err)
    } else {
        fmt.Println("Budget check passed")
    }

    // Test feature validation
    if err := basicMgr.ValidateFeatureAccess("dark_web"); err != nil {
        fmt.Println("Dark web access denied:", err)
        fmt.Println(basicMgr.GetUpgradeMessage("dark_web"))
    }
}
```

### Expected Output

```
Basic Tier Info:
map[daily_budget_usd:0 dark_web_enabled:false is_byok:true max_ai_models:1 monthly_budget_usd:0 organization_id:org-basic-001 swarm_mode:false tier:basic]
Can use dark web? false
Can use SWARM? false

Professional Tier Info:
map[daily_budget_usd:0.83 dark_web_enabled:true is_byok:false max_ai_models:1 monthly_budget_usd:25 organization_id:org-pro-001 swarm_mode:false tier:professional]
Can use dark web? true
Can use SWARM? false
Budget check passed

Dark web access denied: dark web intelligence requires Professional tier or higher (current: basic)
🔒 Dark web intelligence requires Professional tier ($29/endpoint/month)
   Current tier: basic
   Upgrade to access:
   • Credential breach monitoring (15B+ records)
   • Malware hash correlation
   • C2 server detection
   • $25/month AI credits included
```

## Dashboard Testing

### Manual UI Testing

1. Start the dashboard:
```bash
cd aftersec-dashboard
npm run dev
```

2. Navigate to settings or organization page

3. Add the TierStatusBanner component:
```tsx
import TierStatusBanner from '@/components/TierStatusBanner'

// In your page:
<TierStatusBanner orgId="org-basic-001" />
```

4. Test different tiers:
   - Change orgId to org-basic-001, org-pro-001, org-ent-001
   - Verify correct badge displays (FREE/PRO/ENTERPRISE)
   - Check AI budget bar (should be hidden for basic tier)
   - Click upgrade button (basic/pro should show upgrade options)

## Feature Flag Testing

### Test Dark Web Features

```go
tierMgr := client.NewTierManager("professional", "org-pro-001")
features := tierMgr.GetDarkWebFeatures()

fmt.Println("Credential monitoring:", features["credential_monitoring"]) // true
fmt.Println("Daily scans:", features["daily_scans"]) // false (enterprise only)
```

### Test AI Model Selection

```go
// Basic tier - BYOK
basicMgr := client.NewTierManager("basic", "org-basic-001")
fmt.Println(basicMgr.GetRecommendedAIProvider()) // "" (user chooses)
fmt.Println(basicMgr.GetMaxAIModels()) // 1

// Professional tier - auto Gemini
proMgr := client.NewTierManager("professional", "org-pro-001")
fmt.Println(proMgr.GetRecommendedAIProvider()) // "gemini"
fmt.Println(proMgr.GetMaxAIModels()) // 1

// Enterprise tier - SWARM
entMgr := client.NewTierManager("enterprise", "org-ent-001")
fmt.Println(entMgr.GetRecommendedAIProvider()) // "swarm"
fmt.Println(entMgr.GetMaxAIModels()) // 3
```

## Integration Testing

### Full Flow Test

```bash
#!/bin/bash

# 1. Create basic tier organization
ORG_ID=$(curl -X POST "http://localhost:8080/api/v1/organizations" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Org","slug":"test-org","license_tier":"basic"}' \
  | jq -r '.id')

echo "Created organization: $ORG_ID"

# 2. Try to access dark web (should fail)
curl -X GET "http://localhost:8080/api/v1/darkweb/alerts?org_id=$ORG_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: 402 Payment Required

# 3. Upgrade to professional
curl -X POST "http://localhost:8080/api/v1/organizations/upgrade" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"organization_id\":\"$ORG_ID\",\"target_tier\":\"professional\",\"payment_method_id\":\"mock\"}"

# 4. Try dark web access again (should succeed)
curl -X GET "http://localhost:8080/api/v1/darkweb/alerts?org_id=$ORG_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: 200 OK

# 5. Check tier info
curl -X GET "http://localhost:8080/api/v1/organizations/tier?org_id=$ORG_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  | jq '.'
```

## Automated Tests

### Unit Tests

```go
package rest

import (
    "testing"
)

func TestTierHierarchy(t *testing.T) {
    tests := []struct {
        current  string
        required string
        expected bool
    }{
        {"basic", "basic", true},
        {"professional", "basic", true},
        {"enterprise", "basic", true},
        {"basic", "professional", false},
        {"professional", "professional", true},
        {"enterprise", "professional", true},
        {"basic", "enterprise", false},
        {"professional", "enterprise", false},
        {"enterprise", "enterprise", true},
    }

    for _, tt := range tests {
        result := hasRequiredTier(tt.current, tt.required)
        if result != tt.expected {
            t.Errorf("hasRequiredTier(%s, %s) = %v, want %v",
                tt.current, tt.required, result, tt.expected)
        }
    }
}

func TestAIBudgetAllocation(t *testing.T) {
    tests := []struct {
        tier    string
        daily   float64
        monthly float64
    }{
        {"basic", 0, 0},
        {"professional", 0.83, 25.0},
        {"enterprise", 2.50, 75.0},
    }

    for _, tt := range tests {
        daily, monthly := GetAIBudgetForTier(tt.tier)
        if daily != tt.daily || monthly != tt.monthly {
            t.Errorf("GetAIBudgetForTier(%s) = %.2f, %.2f, want %.2f, %.2f",
                tt.tier, daily, monthly, tt.daily, tt.monthly)
        }
    }
}
```

## Common Issues

### Issue: "Missing organization ID" error
**Solution:** Ensure org_id query parameter is included in requests

### Issue: 401 Unauthorized
**Solution:** Check JWT token is valid and not expired

### Issue: Upgrade succeeds but features still locked
**Solution:** Verify organization record was updated in database:
```sql
SELECT id, name, license_tier FROM organizations WHERE id = 'org-xxx';
```

### Issue: AI budget not tracking
**Solution:** Check BudgetTracker is initialized for non-basic tiers

## Next Steps

After testing:
1. Integrate Stripe for real payment processing
2. Add webhook handling for subscription events
3. Implement usage metering
4. Add tier change notifications
5. Create admin panel for tier management
