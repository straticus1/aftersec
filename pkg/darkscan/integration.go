package darkscan

import (
	"context"
	"fmt"
	"time"
)

// IntegrationReport provides detailed scan results for AfterSec integration
type IntegrationReport struct {
	FilePath      string
	Scanned       bool
	Infected      bool
	ThreatLevel   ThreatLevel
	Threats       []Threat
	Engines       []string
	ScanDuration  time.Duration
	Error         error
}

// ThreatLevel represents the severity of detected threats
type ThreatLevel int

const (
	ThreatLevelNone ThreatLevel = iota
	ThreatLevelLow
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelNone:
		return "NONE"
	case ThreatLevelLow:
		return "LOW"
	case ThreatLevelMedium:
		return "MEDIUM"
	case ThreatLevelHigh:
		return "HIGH"
	case ThreatLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ScanWithReport performs a comprehensive scan and returns a detailed report
func (c *Client) ScanWithReport(ctx context.Context, path string) (*IntegrationReport, error) {
	start := time.Now()

	result, err := c.ScanFile(ctx, path)
	duration := time.Since(start)

	report := &IntegrationReport{
		FilePath:     path,
		Scanned:      true,
		Infected:     result.Infected,
		Threats:      result.Threats,
		Engines:      c.getEnabledEngines(),
		ScanDuration: duration,
		Error:        err,
	}

	report.ThreatLevel = c.calculateThreatLevel(result)

	return report, err
}

// RealTimeScan performs a fast scan optimized for EDR real-time protection
// Returns (isBlocked, threatLevel, error)
func (c *Client) RealTimeScan(ctx context.Context, path string, timeoutSeconds int) (bool, ThreatLevel, error) {
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	result, err := c.ScanFile(scanCtx, path)
	if err != nil {
		if err == context.DeadlineExceeded {
			return false, ThreatLevelNone, fmt.Errorf("scan timeout after %d seconds", timeoutSeconds)
		}
		return false, ThreatLevelNone, err
	}

	threatLevel := c.calculateThreatLevel(result)

	shouldBlock := result.Infected && threatLevel >= ThreatLevelHigh

	return shouldBlock, threatLevel, nil
}

// calculateThreatLevel determines overall threat level from scan results
func (c *Client) calculateThreatLevel(result *ScanResult) ThreatLevel {
	if !result.Infected || len(result.Threats) == 0 {
		return ThreatLevelNone
	}

	maxLevel := ThreatLevelLow

	for _, threat := range result.Threats {
		level := parseThreatSeverity(threat.Severity)
		if level > maxLevel {
			maxLevel = level
		}
	}

	// Multiple engines detecting the same threat increases confidence
	if result.EngineCount >= 2 && len(result.Threats) > 0 && maxLevel < ThreatLevelCritical {
		maxLevel++
	}

	return maxLevel
}

// parseThreatSeverity converts string severity to ThreatLevel
func parseThreatSeverity(severity string) ThreatLevel {
	switch severity {
	case "critical", "CRITICAL", "high", "HIGH":
		return ThreatLevelHigh
	case "medium", "MEDIUM", "moderate", "MODERATE":
		return ThreatLevelMedium
	case "low", "LOW", "info", "INFO":
		return ThreatLevelLow
	default:
		return ThreatLevelMedium
	}
}

// getEnabledEngines returns a list of enabled engine names (internal)
func (c *Client) getEnabledEngines() []string {
	var engines []string

	if c.config.Engines.ClamAV.Enabled {
		engines = append(engines, "ClamAV")
	}
	if c.config.Engines.YARA.Enabled {
		engines = append(engines, "YARA")
	}
	if c.config.Engines.CAPA.Enabled {
		engines = append(engines, "CAPA")
	}
	if c.config.Engines.Viper.Enabled {
		engines = append(engines, "Viper")
	}

	return engines
}

// Note: GetEnabledEngines(), IsEnabled(), and GetEngineCount() are now implemented in client.go

// CalculateThreatLevel is a public helper for calculating threat level from scan results
func CalculateThreatLevel(result *ScanResult) ThreatLevel {
	if !result.Infected || len(result.Threats) == 0 {
		return ThreatLevelNone
	}

	maxLevel := ThreatLevelLow

	for _, threat := range result.Threats {
		level := parseThreatSeverity(threat.Severity)
		if level > maxLevel {
			maxLevel = level
		}
	}

	// Multiple engines detecting the same threat increases confidence
	if result.EngineCount >= 2 && len(result.Threats) > 0 && maxLevel < ThreatLevelCritical {
		maxLevel++
	}

	return maxLevel
}

// FormatThreatSummary creates a human-readable summary of threats from ScanResult
func FormatThreatSummary(result *ScanResult) string {
	if !result.Infected || len(result.Threats) == 0 {
		return "No threats detected"
	}

	threatLevel := CalculateThreatLevel(result)
	summary := fmt.Sprintf("Detected %d threat(s) [%s]:\n", len(result.Threats), threatLevel)

	for _, threat := range result.Threats {
		summary += fmt.Sprintf("  - [%s] %s: %s\n", threat.Engine, threat.Name, threat.Description)
	}

	return summary
}
