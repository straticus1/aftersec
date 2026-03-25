package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DarkAPIBaseURL = "https://api.darkapi.io/v1"
)

// DarkAPIClient handles interactions with DarkAPI.io threat intelligence
type DarkAPIClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewDarkAPIClient creates a new DarkAPI.io client
func NewDarkAPIClient(apiKey string) *DarkAPIClient {
	return &DarkAPIClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
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

// CheckBreachedEmail checks if an email has been compromised
func (c *DarkAPIClient) CheckBreachedEmail(ctx context.Context, email string) ([]BreachedAccount, error) {
	endpoint := fmt.Sprintf("%s/breaches/email/%s", DarkAPIBaseURL, email)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// No breaches found
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

	resp, err := c.httpClient.Do(req)
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// IOC not found in threat database
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
		"days":     30, // Last 30 days
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

	resp, err := c.httpClient.Do(req)
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
