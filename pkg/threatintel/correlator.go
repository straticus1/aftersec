package threatintel

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ThreatCorrelator matches local endpoint data with dark web threat intelligence
type ThreatCorrelator struct {
	darkAPI *DarkAPIClient
	cache   *threatCache
	mu      sync.RWMutex
}

// CorrelatedThreat represents a local finding matched with dark web intel
type CorrelatedThreat struct {
	Type        string    `json:"type"` // breached_credential, malicious_hash, c2_connection, dark_web_mention
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"` // 0.0-1.0
	Description string    `json:"description"`
	LocalData   string    `json:"local_data"`   // What was found locally
	ThreatIntel string    `json:"threat_intel"` // What dark web intel says
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Endpoint    string    `json:"endpoint"`
	Remediation string    `json:"remediation"`
}

// threatCache stores recent threat intel lookups to avoid API spam
type threatCache struct {
	iocs      map[string]*cachedIOC
	breaches  map[string]*cachedBreach
	mentions  map[string]*cachedMention
	mu        sync.RWMutex
	ttl       time.Duration
}

type cachedIOC struct {
	ioc       *ThreatIOC
	timestamp time.Time
}

type cachedBreach struct {
	breaches  []BreachedAccount
	timestamp time.Time
}

type cachedMention struct {
	mentions  []DarkWebMention
	timestamp time.Time
}

// NewThreatCorrelator creates a new threat correlation engine
func NewThreatCorrelator(client *DarkAPIClient) *ThreatCorrelator {
	return &ThreatCorrelator{
		darkAPI: client,
		cache: &threatCache{
			iocs:     make(map[string]*cachedIOC),
			breaches: make(map[string]*cachedBreach),
			mentions: make(map[string]*cachedMention),
			ttl:      15 * time.Minute,
		},
	}
}

// GetDarkAPIClient returns the underlying DarkAPI client for direct access
func (tc *ThreatCorrelator) GetDarkAPIClient() *DarkAPIClient {
	return tc.darkAPI
}

// CheckDomainBreaches checks if any accounts from a domain have been breached
func (tc *ThreatCorrelator) CheckDomainBreaches(ctx context.Context, domain string) ([]BreachedAccount, error) {
	return tc.darkAPI.CheckDomainBreaches(ctx, domain)
}

// CheckFileHash checks if a file hash is known malware
func (tc *ThreatCorrelator) CheckFileHash(ctx context.Context, hash string) (*ThreatIOC, error) {
	return tc.darkAPI.CheckFileHash(ctx, hash)
}

// CheckIPAddress checks if an IP is associated with malicious activity
func (tc *ThreatCorrelator) CheckIPAddress(ctx context.Context, ip string) (*ThreatIOC, error) {
	return tc.darkAPI.CheckIPAddress(ctx, ip)
}

// SearchDarkWeb searches dark web forums for keywords
func (tc *ThreatCorrelator) SearchDarkWeb(ctx context.Context, keywords []string) ([]DarkWebMention, error) {
	return tc.darkAPI.SearchDarkWeb(ctx, keywords)
}

// CorrelateProcessHash checks if a running process hash matches known malware
func (tc *ThreatCorrelator) CorrelateProcessHash(ctx context.Context, endpoint, processName, hash string) (*CorrelatedThreat, error) {
	tc.cache.mu.RLock()
	cached, found := tc.cache.iocs[hash]
	tc.cache.mu.RUnlock()

	var ioc *ThreatIOC
	var err error

	if found && time.Since(cached.timestamp) < tc.cache.ttl {
		ioc = cached.ioc
	} else {
		ioc, err = tc.darkAPI.CheckFileHash(ctx, hash)
		if err != nil {
			return nil, fmt.Errorf("failed to check hash: %w", err)
		}

		// Cache the result
		tc.cache.mu.Lock()
		tc.cache.iocs[hash] = &cachedIOC{ioc: ioc, timestamp: time.Now()}
		tc.cache.mu.Unlock()
	}

	// No threat found
	if ioc == nil {
		return nil, nil
	}

	// Build correlated threat
	threat := &CorrelatedThreat{
		Type:        "malicious_hash",
		Severity:    ioc.Severity,
		Confidence:  0.95, // High confidence when hash matches known malware
		Description: fmt.Sprintf("Process '%s' matches known malware: %s", processName, ioc.Description),
		LocalData:   fmt.Sprintf("Process: %s, Hash: %s", processName, hash),
		ThreatIntel: fmt.Sprintf("Known malware from %s. Tags: %v", ioc.Source, ioc.Tags),
		FirstSeen:   ioc.FirstSeen,
		LastSeen:    ioc.LastSeen,
		Endpoint:    endpoint,
		Remediation: "Immediately isolate endpoint, kill process, run memory forensics, check for persistence mechanisms",
	}

	return threat, nil
}

// CorrelateNetworkConnection checks if an IP/domain is a known C2 server
func (tc *ThreatCorrelator) CorrelateNetworkConnection(ctx context.Context, endpoint, remoteIP, remoteDomain string) (*CorrelatedThreat, error) {
	// Try IP first
	var ioc *ThreatIOC
	var err error

	if remoteIP != "" {
		tc.cache.mu.RLock()
		cached, found := tc.cache.iocs[remoteIP]
		tc.cache.mu.RUnlock()

		if found && time.Since(cached.timestamp) < tc.cache.ttl {
			ioc = cached.ioc
		} else {
			ioc, err = tc.darkAPI.CheckIPAddress(ctx, remoteIP)
			if err != nil {
				log.Printf("Failed to check IP %s: %v", remoteIP, err)
			} else {
				tc.cache.mu.Lock()
				tc.cache.iocs[remoteIP] = &cachedIOC{ioc: ioc, timestamp: time.Now()}
				tc.cache.mu.Unlock()
			}
		}
	}

	// Try domain if IP didn't match or wasn't provided
	if ioc == nil && remoteDomain != "" {
		tc.cache.mu.RLock()
		cached, found := tc.cache.iocs[remoteDomain]
		tc.cache.mu.RUnlock()

		if found && time.Since(cached.timestamp) < tc.cache.ttl {
			ioc = cached.ioc
		} else {
			ioc, err = tc.darkAPI.CheckDomain(ctx, remoteDomain)
			if err != nil {
				log.Printf("Failed to check domain %s: %v", remoteDomain, err)
			} else {
				tc.cache.mu.Lock()
				tc.cache.iocs[remoteDomain] = &cachedIOC{ioc: ioc, timestamp: time.Now()}
				tc.cache.mu.Unlock()
			}
		}
	}

	if ioc == nil {
		return nil, nil
	}

	target := remoteIP
	if remoteDomain != "" {
		target = remoteDomain
	}

	threat := &CorrelatedThreat{
		Type:        "c2_connection",
		Severity:    ioc.Severity,
		Confidence:  0.92,
		Description: fmt.Sprintf("Endpoint connected to known malicious infrastructure: %s", target),
		LocalData:   fmt.Sprintf("Remote IP: %s, Domain: %s", remoteIP, remoteDomain),
		ThreatIntel: fmt.Sprintf("Known C2 server from %s. Tags: %v. Last seen: %s", ioc.Source, ioc.Tags, ioc.LastSeen.Format(time.RFC3339)),
		FirstSeen:   ioc.FirstSeen,
		LastSeen:    time.Now(),
		Endpoint:    endpoint,
		Remediation: "Isolate endpoint immediately, block IP/domain at firewall, investigate process making connection, check for data exfiltration",
	}

	return threat, nil
}

// CorrelateUserCredentials checks if endpoint user credentials have been breached
func (tc *ThreatCorrelator) CorrelateUserCredentials(ctx context.Context, endpoint, email string) (*CorrelatedThreat, error) {
	tc.cache.mu.RLock()
	cached, found := tc.cache.breaches[email]
	tc.cache.mu.RUnlock()

	var breaches []BreachedAccount
	var err error

	if found && time.Since(cached.timestamp) < tc.cache.ttl {
		breaches = cached.breaches
	} else {
		breaches, err = tc.darkAPI.CheckBreachedEmail(ctx, email)
		if err != nil {
			return nil, fmt.Errorf("failed to check email: %w", err)
		}

		tc.cache.mu.Lock()
		tc.cache.breaches[email] = &cachedBreach{breaches: breaches, timestamp: time.Now()}
		tc.cache.mu.Unlock()
	}

	if len(breaches) == 0 {
		return nil, nil
	}

	// Get most recent and severe breach
	var mostRecent BreachedAccount
	for _, breach := range breaches {
		if mostRecent.BreachDate.IsZero() || breach.BreachDate.After(mostRecent.BreachDate) {
			mostRecent = breach
		}
	}

	severity := "medium"
	confidence := 0.85
	if mostRecent.Password != "" {
		severity = "high"
		confidence = 0.95
	}

	dataClasses := "N/A"
	if len(mostRecent.DataClasses) > 0 {
		dataClasses = fmt.Sprintf("%v", mostRecent.DataClasses)
	}

	threat := &CorrelatedThreat{
		Type:       "breached_credential",
		Severity:   severity,
		Confidence: confidence,
		Description: fmt.Sprintf("User %s found in %d data breach(es). Most recent: %s (%s)",
			email, len(breaches), mostRecent.Source, mostRecent.BreachDate.Format("2006-01-02")),
		LocalData:   fmt.Sprintf("Endpoint User: %s", email),
		ThreatIntel: fmt.Sprintf("Breached on %s. Exposed data: %s. Password exposed: %v",
			mostRecent.BreachDate.Format("2006-01-02"), dataClasses, mostRecent.Password != ""),
		FirstSeen:   mostRecent.BreachDate,
		LastSeen:    time.Now(),
		Endpoint:    endpoint,
		Remediation: "Force password reset, enable MFA if not already active, review account activity for unauthorized access, educate user on password reuse risks",
	}

	return threat, nil
}

// CorrelateDarkWebMentions searches dark web for company mentions
func (tc *ThreatCorrelator) CorrelateDarkWebMentions(ctx context.Context, orgDomain string, keywords []string) ([]CorrelatedThreat, error) {
	// Add organization domain to keywords
	searchKeywords := append(keywords, orgDomain)

	tc.cache.mu.RLock()
	cacheKey := fmt.Sprintf("%v", searchKeywords)
	cached, found := tc.cache.mentions[cacheKey]
	tc.cache.mu.RUnlock()

	var mentions []DarkWebMention
	var err error

	if found && time.Since(cached.timestamp) < tc.cache.ttl {
		mentions = cached.mentions
	} else {
		mentions, err = tc.darkAPI.SearchDarkWeb(ctx, searchKeywords)
		if err != nil {
			return nil, fmt.Errorf("failed to search dark web: %w", err)
		}

		tc.cache.mu.Lock()
		tc.cache.mentions[cacheKey] = &cachedMention{mentions: mentions, timestamp: time.Now()}
		tc.cache.mu.Unlock()
	}

	var threats []CorrelatedThreat
	for _, mention := range mentions {
		// Only report high-relevance mentions
		if mention.Relevance < 0.7 {
			continue
		}

		severity := "low"
		if mention.Relevance > 0.9 {
			severity = "high"
		} else if mention.Relevance > 0.8 {
			severity = "medium"
		}

		threat := CorrelatedThreat{
			Type:        "dark_web_mention",
			Severity:    severity,
			Confidence:  mention.Relevance,
			Description: fmt.Sprintf("Organization mentioned on dark web %s: %s", mention.Source, mention.Title),
			LocalData:   fmt.Sprintf("Keywords: %v", keywords),
			ThreatIntel: fmt.Sprintf("Source: %s, Author: %s, Posted: %s. Excerpt: %.200s...",
				mention.Source, mention.Author, mention.Timestamp.Format("2006-01-02"), mention.Content),
			FirstSeen:   mention.Timestamp,
			LastSeen:    time.Now(),
			Endpoint:    "organization-wide",
			Remediation: "Investigate context of mention, determine if legitimate threat, monitor for additional mentions, consider threat hunting sweep",
		}

		threats = append(threats, threat)
	}

	return threats, nil
}
