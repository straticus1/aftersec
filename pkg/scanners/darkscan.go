package scanners

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/core"
	"aftersec/pkg/darkscan"
)

// ScanMalware wires darkscancli into the main aftersec posture scan.
// It performs a quick scan on critical persistence locations.
func ScanMalware(addFinding func(core.Finding)) {
	home, err := os.UserHomeDir()
	if err != nil {
		addFinding(core.Finding{
			Category:    "Malware Scan (Deep Execution)",
			Name:        "DarkScan Integration Error",
			Description: "Failed to determine user home directory for configuration.",
			Severity:    core.LogOnly,
			Passed:      false,
			CurrentVal:  "Error",
			ExpectedVal: "Valid config path",
		})
		return
	}

	configPath := filepath.Join(home, ".aftersec", "config.yaml")
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		addFinding(core.Finding{
			Category:    "Malware Scan (Deep Execution)",
			Name:        "DarkScan Configuration Missing",
			Description: "Could not load aftersec daemon config to initialize DarkScan.",
			Severity:    core.LogOnly,
			Passed:      false,
			CurrentVal:  "Error",
			ExpectedVal: "Valid config path",
		})
		return
	}

	if !cfg.Daemon.DarkScan.Enabled {
		addFinding(core.Finding{
			Category:    "Malware Scan (Deep Execution)",
			Name:        "DarkScan Execution",
			Description: "DarkScan multi-engine analysis is disabled in configuration.",
			Severity:    core.LogOnly,
			Passed:      true,
			CurrentVal:  "Disabled",
			ExpectedVal: "Enabled",
		})
		return
	}

	// Always use CLI client for JSON parsing and macro feature stability
	dsClient, err := darkscan.NewCLIClient(&cfg.Daemon.DarkScan, cfg.Daemon.DarkScan.CLIBinaryPath)
	if err != nil {
		addFinding(core.Finding{
			Category:    "Malware Scan (Deep Execution)",
			Name:        "DarkScan Initialization",
			Description: fmt.Sprintf("Failed to initialize darkscancli: %v", err),
			Severity:    core.High,
			Passed:      false,
			CurrentVal:  "Failed",
			ExpectedVal: "Running",
		})
		return
	}
	defer dsClient.Close()

	if dsClient.GetEngineCount() == 0 {
		addFinding(core.Finding{
			Category:    "Malware Scan (Deep Execution)",
			Name:        "DarkScan Constraints",
			Description: "DarkScan is enabled but no engines (ClamAV, YARA, CAPA, etc.) are configured. Scan skipped.",
			Severity:    core.LogOnly,
			Passed:      true,
		})
		return
	}

	// For posture scanning, we target critical persistence paths rather than full disk
	targetPaths := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		filepath.Join(home, "Library", "LaunchAgents"),
	}

	var allResults []*darkscan.ScanResult
	scanStart := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for _, path := range targetPaths {
		// Verify path exists before scanning
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			continue
		}

		res, scanErr := dsClient.ScanDirectory(ctx, path, true)
		if scanErr != nil {
			addFinding(core.Finding{
				Category:    "Malware Scan (Deep Execution)",
				Name:        fmt.Sprintf("Scanning %s", path),
				Description: fmt.Sprintf("Failed to scan directory %s: %v", path, scanErr),
				Severity:    core.Med,
				Passed:      false,
				CurrentVal:  "Error",
				ExpectedVal: "Completed",
			})
			continue
		}
		
		if res != nil {
			allResults = append(allResults, res...)
		}
	}
	
	duration := time.Since(scanStart)

	infectedCount := 0
	for _, result := range allResults {
		if result.Infected {
			infectedCount++
			
			// Map darkscan threats to core findings
			for _, threat := range result.Threats {
				severity := core.High
				if string(threat.Severity) == "Critical" || string(threat.Severity) == "critical" {
					severity = core.Critical
				} else if string(threat.Severity) == "Suspicious" || string(threat.Severity) == "medium" || string(threat.Severity) == "Medium" {
					severity = core.Med
				}

				addFinding(core.Finding{
					Category:    "Advanced Malware Analysis",
					Name:        fmt.Sprintf("%s (%s)", threat.Name, threat.Engine),
					Description: fmt.Sprintf("Threat detected in %s: %s", result.FilePath, threat.Description),
					Severity:    severity,
					Passed:      false,
					CurrentVal:  "Infected",
					ExpectedVal: "Clean",
					RemediationScript: fmt.Sprintf("aftersec malware-scan --quarantine %s", result.FilePath),
				})
			}
		}
	}

	if infectedCount == 0 {
		addFinding(core.Finding{
			Category:    "Malware Scan (Deep Execution)",
			Name:        "DarkScan Persistent State Verification",
			Description: fmt.Sprintf("Scanned critical system persistence paths using %d engines.", dsClient.GetEngineCount()),
			Severity:    core.LogOnly,
			Passed:      true,
			CurrentVal:  fmt.Sprintf("Clean (%s)", duration.Round(time.Millisecond)),
			ExpectedVal: "Clean",
		})
	}
}
