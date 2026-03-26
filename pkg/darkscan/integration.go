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
	ThreatNone ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatNone:
		return "NONE"
	case ThreatLow:
		return "LOW"
	case ThreatMedium:
		return "MEDIUM"
	case ThreatHigh:
		return "HIGH"
	case ThreatCritical:
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
			return false, ThreatNone, fmt.Errorf("scan timeout after %d seconds", timeoutSeconds)
		}
		return false, ThreatNone, err
	}

	threatLevel := c.calculateThreatLevel(result)

	shouldBlock := result.Infected && threatLevel >= ThreatHigh

	return shouldBlock, threatLevel, nil
}

// calculateThreatLevel determines overall threat level from scan results
func (c *Client) calculateThreatLevel(result *ScanResult) ThreatLevel {
	if !result.Infected || len(result.Threats) == 0 {
		return ThreatNone
	}

	maxLevel := ThreatLow

	for _, threat := range result.Threats {
		level := parseThreatSeverity(threat.Severity)
		if level > maxLevel {
			maxLevel = level
		}
	}

	// Multiple engines detecting the same threat increases confidence
	if result.EngineCount >= 2 && len(result.Threats) > 0 && maxLevel < ThreatCritical {
		maxLevel++
	}

	return maxLevel
}

// parseThreatSeverity converts string severity to ThreatLevel
func parseThreatSeverity(severity string) ThreatLevel {
	switch severity {
	case "critical", "CRITICAL", "high", "HIGH":
		return ThreatHigh
	case "medium", "MEDIUM", "moderate", "MODERATE":
		return ThreatMedium
	case "low", "LOW", "info", "INFO":
		return ThreatLow
	default:
		return ThreatMedium
	}
}

// getEnabledEngines returns a list of enabled engine names
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

// IsEnabled returns whether DarkScan integration is enabled
func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}

// GetEngineCount returns the number of enabled engines
func (c *Client) GetEngineCount() int {
	return len(c.getEnabledEngines())
}

// FormatThreatSummary creates a human-readable summary of threats
func FormatThreatSummary(report *IntegrationReport) string {
	if !report.Infected {
		return "No threats detected"
	}

	summary := fmt.Sprintf("Detected %d threat(s) [%s]:\n", len(report.Threats), report.ThreatLevel)

	for _, threat := range report.Threats {
		summary += fmt.Sprintf("  - [%s] %s: %s\n", threat.Engine, threat.Name, threat.Description)
	}

	return summary
}
