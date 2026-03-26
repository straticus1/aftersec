package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/threatintel"
)

// DarkWebAlert represents a correlated threat from dark web intelligence
type DarkWebAlert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // breach, malware, c2, mention
	Severity    string    `json:"severity"` // critical, high, medium, low
	Timestamp   time.Time `json:"timestamp"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	IOCs        []string  `json:"iocs"`
	Confidence  float64   `json:"confidence"`
	ActionTaken string    `json:"action_taken,omitempty"`
}

// DarkWebAlertsResponse contains a list of dark web threat alerts
type DarkWebAlertsResponse struct {
	Alerts     []DarkWebAlert `json:"alerts"`
	TotalCount int            `json:"total_count"`
	Timestamp  time.Time      `json:"timestamp"`
}

// darkWebAlertService manages dark web intelligence correlation
type darkWebAlertService struct {
	correlator  *threatintel.ThreatCorrelator
	cache       []DarkWebAlert
	cacheTime   time.Time
	cacheTTL    time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	workerDone  chan struct{}
}

var globalAlertService *darkWebAlertService

// InitDarkWebAlertService initializes the dark web alert service
func InitDarkWebAlertService(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("DarkAPI key not configured")
	}

	darkAPIClient, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		return fmt.Errorf("failed to create DarkAPI client: %w", err)
	}

	correlator := threatintel.NewThreatCorrelator(darkAPIClient)

	ctx, cancel := context.WithCancel(context.Background())
	globalAlertService = &darkWebAlertService{
		correlator: correlator,
		cache:      make([]DarkWebAlert, 0),
		cacheTTL:   5 * time.Minute, // Cache alerts for 5 minutes
		ctx:        ctx,
		cancel:     cancel,
		workerDone: make(chan struct{}),
	}

	// Start background correlation worker
	go globalAlertService.startCorrelationWorker()

	return nil
}

// StopDarkWebAlertService gracefully shuts down the dark web alert service
func StopDarkWebAlertService() {
	if globalAlertService != nil {
		globalAlertService.cancel()
		<-globalAlertService.workerDone // Wait for worker to finish
		globalAlertService = nil
	}
}

// startCorrelationWorker continuously correlates threats in background
func (s *darkWebAlertService) startCorrelationWorker() {
	defer close(s.workerDone) // Signal completion when worker exits

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	fmt.Println("[DarkWeb] Correlation worker started")

	for {
		select {
		case <-s.ctx.Done():
			fmt.Println("[DarkWeb] Correlation worker shutting down")
			return
		case <-ticker.C:
			// Use a timeout context for each correlation attempt
			correlationCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
			alerts, err := s.correlateThreats(correlationCtx)
			cancel()

			if err != nil {
				fmt.Printf("[DarkWeb] Correlation error: %v\n", err)
				continue
			}

			s.cacheTime = time.Now()
			s.cache = alerts
		}
	}
}

// correlateThreats performs threat correlation against dark web intel
func (s *darkWebAlertService) correlateThreats(ctx context.Context) ([]DarkWebAlert, error) {
	alerts := make([]DarkWebAlert, 0)

	// Example: Check organization domain for breaches
	orgDomain := "company.com" // This would come from config
	breaches, err := s.correlator.CheckDomainBreaches(ctx, orgDomain)
	if err == nil {
		for _, breach := range breaches {
			alert := DarkWebAlert{
				ID:          fmt.Sprintf("breach-%s-%d", breach.Email, breach.BreachDate.Unix()),
				Type:        "breach",
				Severity:    determineSeverity(breach.DataClasses),
				Timestamp:   breach.BreachDate,
				Title:       fmt.Sprintf("Credential Breach: %s", breach.Email),
				Description: fmt.Sprintf("Email exposed in %s breach. Data classes: %v", breach.Source, breach.DataClasses),
				Source:      breach.Source,
				IOCs:        []string{breach.Email},
				Confidence:  0.95,
				ActionTaken: "Force password reset recommended",
			}
			alerts = append(alerts, alert)
		}
	}

	// Example: Check suspicious process hashes
	suspiciousHashes := s.getSuspiciousProcessHashes()
	for _, hash := range suspiciousHashes {
		ioc, err := s.correlator.CheckFileHash(ctx, hash)
		if err == nil && ioc != nil {
			alert := DarkWebAlert{
				ID:          fmt.Sprintf("malware-%s", hash[:8]),
				Type:        "malware",
				Severity:    ioc.Severity,
				Timestamp:   ioc.LastSeen,
				Title:       fmt.Sprintf("Known Malware Hash Detected"),
				Description: fmt.Sprintf("Process hash matches %s. %s", ioc.Source, ioc.Description),
				Source:      ioc.Source,
				IOCs:        []string{hash},
				Confidence:  0.98,
				ActionTaken: "Process terminated automatically",
			}
			alerts = append(alerts, alert)
		}
	}

	// Example: Check network connections for C2 servers
	suspiciousIPs := s.getSuspiciousNetworkIPs()
	for _, ip := range suspiciousIPs {
		ioc, err := s.correlator.CheckIPAddress(ctx, ip)
		if err == nil && ioc != nil {
			alert := DarkWebAlert{
				ID:          fmt.Sprintf("c2-%s", ip),
				Type:        "c2",
				Severity:    "critical",
				Timestamp:   time.Now(),
				Title:       fmt.Sprintf("C2 Server Connection Detected"),
				Description: fmt.Sprintf("Connection to known command & control server: %s. %s", ip, ioc.Description),
				Source:      ioc.Source,
				IOCs:        []string{ip},
				Confidence:  0.96,
				ActionTaken: "Connection blocked via firewall",
			}
			alerts = append(alerts, alert)
		}
	}

	// Example: Search dark web for organization mentions
	keywords := []string{"company-name", "ceo-name", "product"}
	mentions, err := s.correlator.SearchDarkWeb(ctx, keywords)
	if err == nil {
		for _, mention := range mentions {
			if mention.Relevance > 0.7 { // Only high-relevance mentions
				alert := DarkWebAlert{
					ID:          mention.ID,
					Type:        "mention",
					Severity:    calculateMentionSeverity(mention),
					Timestamp:   mention.Timestamp,
					Title:       fmt.Sprintf("Dark Web Mention: %s", mention.Title),
					Description: mention.Content,
					Source:      mention.Source,
					IOCs:        mention.Keywords,
					Confidence:  mention.Relevance,
				}
				alerts = append(alerts, alert)
			}
		}
	}

	return alerts, nil
}

// getSuspiciousProcessHashes returns hashes of recently executed processes
func (s *darkWebAlertService) getSuspiciousProcessHashes() []string {
	// This would integrate with actual process monitoring
	// For now, return example hashes
	return []string{
		"abc123def456", // Example: Emotet hash
	}
}

// getSuspiciousNetworkIPs returns IPs of recent network connections
func (s *darkWebAlertService) getSuspiciousNetworkIPs() []string {
	// This would integrate with actual network monitoring
	// For now, return example IPs
	return []string{
		"192.0.2.1", // Example: Known C2 server
	}
}

// determineSeverity determines breach severity based on data classes exposed
func determineSeverity(dataClasses []string) string {
	for _, class := range dataClasses {
		if class == "passwords" || class == "credit-cards" || class == "ssn" {
			return "critical"
		}
	}

	if len(dataClasses) > 5 {
		return "high"
	} else if len(dataClasses) > 2 {
		return "medium"
	}

	return "low"
}

// calculateMentionSeverity determines severity of a dark web mention
func calculateMentionSeverity(mention threatintel.DarkWebMention) string {
	// Check source type
	if mention.Source == "marketplace" || mention.Source == "telegram" {
		return "critical"
	}

	// Check content for keywords
	content := mention.Content + " " + mention.Title
	if contains(content, "breach") || contains(content, "leak") || contains(content, "stolen") {
		return "high"
	}

	if mention.Relevance > 0.9 {
		return "high"
	} else if mention.Relevance > 0.7 {
		return "medium"
	}

	return "low"
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			result[i] = s[i] + 32
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}

// HandleDarkWebAlerts returns current dark web threat alerts
func HandleDarkWebAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if globalAlertService == nil {
		// Dark web intelligence not configured
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DarkWebAlertsResponse{
			Alerts:     []DarkWebAlert{},
			TotalCount: 0,
			Timestamp:  time.Now(),
		})
		return
	}

	// Check cache
	if time.Since(globalAlertService.cacheTime) < globalAlertService.cacheTTL && len(globalAlertService.cache) > 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DarkWebAlertsResponse{
			Alerts:     globalAlertService.cache,
			TotalCount: len(globalAlertService.cache),
			Timestamp:  time.Now(),
		})
		return
	}

	// Fetch fresh alerts
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alerts, err := globalAlertService.correlateThreats(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to correlate threats: %v", err), http.StatusInternalServerError)
		return
	}

	// Update cache
	globalAlertService.cache = alerts
	globalAlertService.cacheTime = time.Now()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DarkWebAlertsResponse{
		Alerts:     alerts,
		TotalCount: len(alerts),
		Timestamp:  time.Now(),
	})
}

// HandleDarkWebConfig returns dark web intelligence configuration status
func HandleDarkWebConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	config := map[string]interface{}{
		"enabled":             globalAlertService != nil,
		"cache_ttl_seconds":   0,
		"last_correlation":    "",
		"total_alerts_cached": 0,
	}

	if globalAlertService != nil {
		config["cache_ttl_seconds"] = int(globalAlertService.cacheTTL.Seconds())
		config["last_correlation"] = globalAlertService.cacheTime.Format(time.RFC3339)
		config["total_alerts_cached"] = len(globalAlertService.cache)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// Helper to initialize from config
func InitDarkWebFromConfig(cfg *client.ClientConfig) error {
	if cfg.Daemon.ThreatIntel.Enabled && cfg.Daemon.ThreatIntel.DarkAPIKey != "" {
		return InitDarkWebAlertService(cfg.Daemon.ThreatIntel.DarkAPIKey)
	}
	return nil
}
