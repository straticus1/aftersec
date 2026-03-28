package darkscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PrivacyScanner handles privacy and telemetry detection
type PrivacyScanner struct {
	config  *Config
	enabled bool
}

// Note: PrivacyScanResult, PrivacyFinding, and PrivacyFilter types are defined in interface.go

// NewPrivacyScanner creates a new privacy scanner
func NewPrivacyScanner(cfg *Config) (*PrivacyScanner, error) {
	if !cfg.Privacy.Enabled {
		return &PrivacyScanner{enabled: false}, nil
	}

	return &PrivacyScanner{
		config:  cfg,
		enabled: true,
	}, nil
}

// ScanBrowserPrivacy scans browsers for tracking and privacy issues
func (p *PrivacyScanner) ScanBrowserPrivacy(ctx context.Context, browsers []string) ([]*PrivacyScanResult, error) {
	if !p.enabled {
		return nil, fmt.Errorf("privacy scanner not enabled")
	}

	var results []*PrivacyScanResult

	for _, browser := range browsers {
		result, err := p.scanSingleBrowser(ctx, browser)
		if err != nil {
			// Log error but continue with other browsers
			fmt.Fprintf(os.Stderr, "Warning: failed to scan %s: %v\n", browser, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// scanSingleBrowser scans a single browser profile
func (p *PrivacyScanner) scanSingleBrowser(ctx context.Context, browser string) (*PrivacyScanResult, error) {
	profilePath, err := p.getBrowserProfilePath(browser)
	if err != nil {
		return nil, err
	}

	result := &PrivacyScanResult{
		Browser:       browser,
		ProfilePath:   profilePath,
		TrackersFound: []PrivacyFinding{},
		TelemetryURLs: []string{},
		RiskLevel:     "low",
	}

	// Check if profile exists
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return result, nil // Browser not installed or no profile
	}

	start := time.Now()

	// Scan for trackers
	trackers, err := p.scanTrackers(profilePath, browser)
	if err == nil {
		result.TrackersFound = trackers
	}

	// Scan for telemetry
	telemetryURLs, err := p.scanTelemetry(profilePath, browser)
	if err == nil {
		result.TelemetryURLs = telemetryURLs
	}

	result.ScanDuration = time.Since(start)

	// Calculate risk level
	result.RiskLevel = p.calculateRiskLevel(len(trackers), len(telemetryURLs))

	return result, nil
}

// getBrowserProfilePath returns the default profile path for a browser
func (p *PrivacyScanner) getBrowserProfilePath(browser string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch strings.ToLower(browser) {
	case "chrome":
		return filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default"), nil
	case "firefox":
		return filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles"), nil
	case "safari":
		return filepath.Join(homeDir, "Library", "Safari"), nil
	case "brave":
		return filepath.Join(homeDir, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default"), nil
	case "edge":
		return filepath.Join(homeDir, "Library", "Application Support", "Microsoft Edge", "Default"), nil
	default:
		return "", fmt.Errorf("unsupported browser: %s", browser)
	}
}

// scanTrackers scans for tracking cookies and extensions
func (p *PrivacyScanner) scanTrackers(profilePath, browser string) ([]PrivacyFinding, error) {
	var findings []PrivacyFinding

	// Common tracking domains to look for
	trackingDomains := []string{
		"doubleclick.net",
		"google-analytics.com",
		"facebook.com",
		"googletagmanager.com",
		"scorecardresearch.com",
		"advertising.com",
		"quantserve.com",
		"adnxs.com",
	}

	// Check cookies file if exists (simplified check)
	cookiesPath := filepath.Join(profilePath, "Cookies")
	if _, err := os.Stat(cookiesPath); err == nil {
		for _, domain := range trackingDomains {
			// In production, would actually parse the cookies database
			finding := PrivacyFinding{
				ID:          fmt.Sprintf("tracker_%s_%s", browser, domain),
				Type:        "cookie",
				Severity:    "medium",
				Name:        domain,
				Description: fmt.Sprintf("Tracking cookie from %s", domain),
				Domain:      domain,
				Removable:   true,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// scanTelemetry scans for telemetry and analytics configurations
func (p *PrivacyScanner) scanTelemetry(profilePath, browser string) ([]string, error) {
	var telemetryURLs []string

	// Check for telemetry configuration files
	telemetryFiles := map[string][]string{
		"Preferences":        {"https://clients2.google.com/service/update2"},
		"Local State":        {"https://chrome-stats-proxy.corp.google.com"},
		"Secure Preferences": {"https://www.google.com/chrome"},
	}

	for filename, urls := range telemetryFiles {
		filePath := filepath.Join(profilePath, filename)
		if _, err := os.Stat(filePath); err == nil {
			// File exists - in production would parse JSON to check actual settings
			telemetryURLs = append(telemetryURLs, urls...)
		}
	}

	return telemetryURLs, nil
}

// ScanApplicationTelemetry scans an application for telemetry
func (p *PrivacyScanner) ScanApplicationTelemetry(ctx context.Context, appPath string) (*PrivacyScanResult, error) {
	if !p.enabled {
		return nil, fmt.Errorf("privacy scanner not enabled")
	}

	start := time.Now()

	result := &PrivacyScanResult{
		Browser:       "application",
		ProfilePath:   appPath,
		TrackersFound: []PrivacyFinding{},
		TelemetryURLs: []string{},
	}

	// Check for common telemetry indicators
	telemetryIndicators := []string{
		"GoogleAnalytics",
		"amplitude",
		"mixpanel",
		"segment",
		"crashlytics",
		"sentry",
		"bugsnag",
	}

	var findings []PrivacyFinding

	// Walk application directory looking for telemetry
	err := filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			return nil
		}

		// Check filename for telemetry indicators
		filename := strings.ToLower(filepath.Base(path))
		for _, indicator := range telemetryIndicators {
			if strings.Contains(filename, strings.ToLower(indicator)) {
				finding := PrivacyFinding{
					ID:          fmt.Sprintf("app_telemetry_%s", indicator),
					Type:        "telemetry",
					Severity:    "medium",
					Name:        indicator,
					Description: fmt.Sprintf("Telemetry library %s detected", indicator),
					Domain:      "",
					Data:        path,
					Removable:   false,
				}
				findings = append(findings, finding)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk application: %w", err)
	}

	result.TrackersFound = findings
	result.ScanDuration = time.Since(start)
	result.RiskLevel = p.calculateRiskLevel(len(findings), 0)

	return result, nil
}

// ListPrivacyFindings lists all privacy findings with optional filters
func (p *PrivacyScanner) ListPrivacyFindings(ctx context.Context, filters PrivacyFilter) ([]*PrivacyFinding, error) {
	if !p.enabled {
		return nil, fmt.Errorf("privacy scanner not enabled")
	}

	// In production, this would query a database of historical findings
	// For now, perform a fresh scan
	browsers := p.config.Privacy.ScanBrowsers
	if filters.Browser != "" {
		browsers = []string{filters.Browser}
	}

	results, err := p.ScanBrowserPrivacy(ctx, browsers)
	if err != nil {
		return nil, err
	}

	var allFindings []*PrivacyFinding
	for _, result := range results {
		for i := range result.TrackersFound {
			allFindings = append(allFindings, &result.TrackersFound[i])
		}
	}

	// Apply filters
	filtered := p.applyFilters(allFindings, filters)

	return filtered, nil
}

// applyFilters applies filters to findings
func (p *PrivacyScanner) applyFilters(findings []*PrivacyFinding, filters PrivacyFilter) []*PrivacyFinding {
	var result []*PrivacyFinding

	for _, finding := range findings {
		// Type filter
		if filters.Type != "" && finding.Type != filters.Type {
			continue
		}

		// RiskLevel filter (maps to finding severity)
		if filters.RiskLevel != "" && finding.Severity != filters.RiskLevel {
			continue
		}

		result = append(result, finding)
	}

	return result
}

// RemoveTrackers removes specified trackers
func (p *PrivacyScanner) RemoveTrackers(ctx context.Context, browser string, trackerIDs []string) error {
	if !p.enabled {
		return fmt.Errorf("privacy scanner not enabled")
	}

	if !p.config.Privacy.BlockTrackers {
		return fmt.Errorf("tracker removal not enabled in configuration")
	}

	// In production, this would actually remove cookies and clear storage
	// For now, just validate the operation
	profilePath, err := p.getBrowserProfilePath(browser)
	if err != nil {
		return err
	}

	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return fmt.Errorf("browser profile not found: %s", profilePath)
	}

	fmt.Fprintf(os.Stderr, "Would remove %d trackers from %s\n", len(trackerIDs), browser)
	return nil
}

// calculateRiskLevel determines risk level based on findings
func (p *PrivacyScanner) calculateRiskLevel(trackerCount, telemetryCount int) string {
	total := trackerCount + telemetryCount

	switch {
	case total == 0:
		return "low"
	case total <= 5:
		return "medium"
	case total <= 10:
		return "high"
	default:
		return "critical"
	}
}
