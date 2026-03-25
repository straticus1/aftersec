package threatintel

import (
	"context"
	"fmt"
	"log"
	"os/user"
	"sync"
	"time"
)

// CredentialMonitor periodically checks endpoint user credentials against dark web breaches
type CredentialMonitor struct {
	correlator     *ThreatCorrelator
	checkInterval  time.Duration
	orgDomain      string
	alertCallback  func(threat *CorrelatedThreat)
	mu             sync.RWMutex
	lastCheck      time.Time
	knownBreaches  map[string]time.Time // email -> last check time
}

// NewCredentialMonitor creates a new credential monitoring service
func NewCredentialMonitor(apiKey string, orgDomain string, checkInterval time.Duration, callback func(*CorrelatedThreat)) *CredentialMonitor {
	return &CredentialMonitor{
		correlator:    NewThreatCorrelator(apiKey),
		checkInterval: checkInterval,
		orgDomain:     orgDomain,
		alertCallback: callback,
		knownBreaches: make(map[string]time.Time),
	}
}

// Start begins the credential monitoring loop
func (cm *CredentialMonitor) Start(ctx context.Context) error {
	log.Println("[ThreatIntel] Starting credential monitor...")

	// Initial check
	if err := cm.checkAllUsers(ctx); err != nil {
		log.Printf("[ThreatIntel] Initial credential check failed: %v", err)
	}

	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[ThreatIntel] Credential monitor shutting down")
			return ctx.Err()
		case <-ticker.C:
			if err := cm.checkAllUsers(ctx); err != nil {
				log.Printf("[ThreatIntel] Credential check failed: %v", err)
			}
		}
	}
}

// checkAllUsers checks all local user accounts for breached credentials
func (cm *CredentialMonitor) checkAllUsers(ctx context.Context) error {
	cm.mu.Lock()
	cm.lastCheck = time.Now()
	cm.mu.Unlock()

	// Get current system user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Build email from username and org domain
	var emails []string
	if cm.orgDomain != "" {
		emails = append(emails, fmt.Sprintf("%s@%s", currentUser.Username, cm.orgDomain))
	}

	// Also check if username is already an email
	if isEmail(currentUser.Username) {
		emails = append(emails, currentUser.Username)
	}

	log.Printf("[ThreatIntel] Checking %d email(s) for breaches", len(emails))

	for _, email := range emails {
		// Skip if we checked this recently (within last 6 hours)
		cm.mu.RLock()
		lastCheck, exists := cm.knownBreaches[email]
		cm.mu.RUnlock()

		if exists && time.Since(lastCheck) < 6*time.Hour {
			continue
		}

		threat, err := cm.correlator.CorrelateUserCredentials(ctx, getHostname(), email)
		if err != nil {
			log.Printf("[ThreatIntel] Failed to check %s: %v", email, err)
			continue
		}

		// Update last check time
		cm.mu.Lock()
		cm.knownBreaches[email] = time.Now()
		cm.mu.Unlock()

		if threat != nil {
			log.Printf("[ThreatIntel] BREACH DETECTED: %s - %s", email, threat.Description)
			if cm.alertCallback != nil {
				cm.alertCallback(threat)
			}
		} else {
			log.Printf("[ThreatIntel] No breaches found for %s", email)
		}
	}

	return nil
}

// CheckUser manually checks a specific user email
func (cm *CredentialMonitor) CheckUser(ctx context.Context, email string) (*CorrelatedThreat, error) {
	threat, err := cm.correlator.CorrelateUserCredentials(ctx, getHostname(), email)
	if err != nil {
		return nil, err
	}

	if threat != nil {
		cm.mu.Lock()
		cm.knownBreaches[email] = time.Now()
		cm.mu.Unlock()

		if cm.alertCallback != nil {
			cm.alertCallback(threat)
		}
	}

	return threat, nil
}

// CheckDomainBreaches checks all breached accounts from the organization domain
func (cm *CredentialMonitor) CheckDomainBreaches(ctx context.Context) ([]BreachedAccount, error) {
	if cm.orgDomain == "" {
		return nil, fmt.Errorf("organization domain not configured")
	}

	log.Printf("[ThreatIntel] Checking all breaches for domain: %s", cm.orgDomain)
	breaches, err := cm.correlator.darkAPI.CheckDomainBreaches(ctx, cm.orgDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to check domain breaches: %w", err)
	}

	log.Printf("[ThreatIntel] Found %d breached accounts for %s", len(breaches), cm.orgDomain)

	// Alert on each breach
	for _, breach := range breaches {
		threat := &CorrelatedThreat{
			Type:       "breached_credential",
			Severity:   determineSeverity(breach),
			Confidence: 0.90,
			Description: fmt.Sprintf("Organization account %s found in breach: %s",
				breach.Email, breach.Source),
			LocalData: fmt.Sprintf("Domain: %s, Email: %s", cm.orgDomain, breach.Email),
			ThreatIntel: fmt.Sprintf("Breach Date: %s, Data Classes: %v",
				breach.BreachDate.Format("2006-01-02"), breach.DataClasses),
			FirstSeen:   breach.BreachDate,
			LastSeen:    time.Now(),
			Endpoint:    "organization-wide",
			Remediation: "Force password reset for affected user, enable MFA, audit account activity",
		}

		if cm.alertCallback != nil {
			cm.alertCallback(threat)
		}
	}

	return breaches, nil
}

// GetStats returns monitoring statistics
func (cm *CredentialMonitor) GetStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return map[string]interface{}{
		"last_check":      cm.lastCheck,
		"checked_emails":  len(cm.knownBreaches),
		"check_interval":  cm.checkInterval.String(),
		"org_domain":      cm.orgDomain,
	}
}

// Helper functions
func isEmail(s string) bool {
	// Simple email detection
	return len(s) > 0 && contains(s, "@") && contains(s, ".")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func getHostname() string {
	// Use os.Hostname() in production
	return "local-endpoint"
}

func determineSeverity(breach BreachedAccount) string {
	if breach.Password != "" {
		return "high"
	}

	// Check for sensitive data classes
	for _, dataClass := range breach.DataClasses {
		if dataClass == "Passwords" || dataClass == "Password hints" ||
		   dataClass == "Credit cards" || dataClass == "Social security numbers" {
			return "high"
		}
	}

	return "medium"
}
