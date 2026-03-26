package forensics

import (
	"aftersec/pkg/darkscan"
	"context"
	"fmt"
)

// EnhancedCapabilitiesReport extends CapabilitiesReport with DarkScan results
type EnhancedCapabilitiesReport struct {
	*CapabilitiesReport
	DarkScanResults *DarkScanResults
}

// DarkScanResults holds the results from DarkScan engines
type DarkScanResults struct {
	Scanned     bool
	Infected    bool
	ThreatLevel string
	Threats     []DarkScanThreat
	Engines     []string
}

// DarkScanThreat represents a threat detected by DarkScan
type DarkScanThreat struct {
	Name        string
	Severity    string
	Description string
	Engine      string
}

// AnalyzeWithDarkScan performs both forensics analysis and DarkScan malware detection
func AnalyzeWithDarkScan(ctx context.Context, path string, dsClient *darkscan.Client) (*EnhancedCapabilitiesReport, error) {
	capReport, err := AnalyzePath(path)
	if err != nil {
		return nil, fmt.Errorf("forensics analysis failed: %w", err)
	}

	enhanced := &EnhancedCapabilitiesReport{
		CapabilitiesReport: capReport,
	}

	if dsClient != nil && dsClient.IsEnabled() {
		report, err := dsClient.ScanWithReport(ctx, path)
		if err != nil {
			return enhanced, fmt.Errorf("DarkScan analysis failed: %w", err)
		}

		enhanced.DarkScanResults = &DarkScanResults{
			Scanned:     report.Scanned,
			Infected:    report.Infected,
			ThreatLevel: report.ThreatLevel.String(),
			Engines:     report.Engines,
		}

		for _, threat := range report.Threats {
			enhanced.DarkScanResults.Threats = append(enhanced.DarkScanResults.Threats, DarkScanThreat{
				Name:        threat.Name,
				Severity:    threat.Severity,
				Description: threat.Description,
				Engine:      threat.Engine,
			})
		}

		// Elevate threat score if DarkScan detects malware
		if report.Infected {
			switch report.ThreatLevel {
			case darkscan.ThreatCritical, darkscan.ThreatHigh:
				enhanced.ThreatScore = Malicious
			case darkscan.ThreatMedium:
				if enhanced.ThreatScore < Suspicious {
					enhanced.ThreatScore = Suspicious
				}
			}
		}
	}

	return enhanced, nil
}

// QuickMalwareScan performs a fast DarkScan check for real-time protection
func QuickMalwareScan(ctx context.Context, path string, dsClient *darkscan.Client) (bool, error) {
	if dsClient == nil || !dsClient.IsEnabled() {
		return false, nil
	}

	return dsClient.QuickScan(ctx, path)
}
