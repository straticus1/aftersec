package cmd

import (
	stdcontext "context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var darkscanStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show DarkScan platform status",
	Long: `Display comprehensive status information:

• Enabled engines and their status
• Quarantine statistics
• Hash store statistics
• Rule repository information
• Configuration details
• Connection status (daemon vs library)

Example:
  aftersec darkscan status`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		if outputFormat == "json" {
			status := buildStatusJSON(scanner, cfg, ctx)
			outputJSON(JSONOutput{
				Success: true,
				Data:    status,
			})
			return
		}

		printStatus(scanner, cfg, ctx)
	},
}

func printStatus(scanner *darkscan.Client, cfg *darkscan.Config, ctx stdcontext.Context) {
	fmt.Println("🛡️  AfterSec DarkScan Platform Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Connection Status
	connStatus := scanner.GetConnectionStatus()
	fmt.Printf("Connection:  %s mode\n", connStatus.Mode)
	fmt.Printf("Status:      %s\n\n", func() string {
		if connStatus.DaemonConnected {
			return "✅ Connected to daemon"
		}
		return "📚 Using library mode"
	}())

	// Scanning Engines
	engines := scanner.GetEnabledEngines()
	fmt.Printf("Scanning Engines (%d active):\n", len(engines))
	for _, engine := range engines {
		fmt.Printf("  ✓ %s\n", engine)
	}
	fmt.Println()

	// Quarantine Statistics
	if cfg.Quarantine.Enabled {
		quarantineList, err := scanner.ListQuarantine(ctx)
		if err == nil {
			fmt.Printf("Quarantine:  ✅ Enabled\n")
			fmt.Printf("  Files:     %d quarantined\n", len(quarantineList))
			fmt.Printf("  Path:      %s\n", cfg.Quarantine.Path)
			fmt.Printf("  Encrypted: %v\n", cfg.Quarantine.Encrypt)
			fmt.Println()
		}
	} else {
		fmt.Println("Quarantine:  ❌ Disabled")
		fmt.Println()
	}

	// Hash Store Statistics
	if cfg.HashStore.Enabled {
		// Get recent history to show stats
		filter := darkscan.HistoryFilter{
			Limit: 1000,
		}
		history, err := scanner.GetScanHistory(ctx, filter)
		if err == nil {
			infected := 0
			for _, entry := range history {
				if entry.Infected {
					infected++
				}
			}
			fmt.Printf("Hash Store:  ✅ Enabled\n")
			fmt.Printf("  Total:     %d scans\n", len(history))
			fmt.Printf("  Infected:  %d files\n", infected)
			fmt.Printf("  Clean:     %d files\n", len(history)-infected)
			fmt.Printf("  Retention: %d days\n", cfg.HashStore.RetentionDays)
			fmt.Println()
		}
	} else {
		fmt.Println("Hash Store:  ❌ Disabled")
		fmt.Println()
	}

	// Privacy Scanner
	if cfg.Privacy.Enabled {
		fmt.Printf("Privacy:     ✅ Enabled\n")
		fmt.Printf("  Browsers:  %v\n", cfg.Privacy.ScanBrowsers)
		fmt.Printf("  Blocking:  %v\n", cfg.Privacy.BlockTrackers)
		fmt.Println()
	} else {
		fmt.Println("Privacy:     ❌ Disabled")
		fmt.Println()
	}

	// Rule Manager
	if cfg.RuleManager.Enabled {
		ruleInfo, err := scanner.GetRuleInfo()
		if err == nil {
			fmt.Printf("Rules:       ✅ Enabled\n")
			fmt.Printf("  Total:     %d rules\n", ruleInfo.TotalRules)
			fmt.Printf("  Repos:     %d configured\n", len(ruleInfo.Repositories))
			if !ruleInfo.LastUpdate.IsZero() {
				fmt.Printf("  Updated:   %s\n", ruleInfo.LastUpdate.Format("2006-01-02 15:04"))
			}
			fmt.Printf("  Auto:      %v\n", cfg.RuleManager.AutoUpdate)
			fmt.Println()
		}
	} else {
		fmt.Println("Rules:       ❌ Disabled")
		fmt.Println()
	}

	// Profiles
	if cfg.Profiles.Enabled {
		profiles, err := scanner.ListProfiles()
		if err == nil {
			fmt.Printf("Profiles:    ✅ Enabled (%d available)\n", len(profiles))
			fmt.Printf("  Default:   %s\n", cfg.Profiles.DefaultProfile)
			fmt.Println()
		}
	} else {
		fmt.Println("Profiles:    ❌ Disabled")
		fmt.Println()
	}

	// File Type Detection
	if cfg.FileType.Enabled {
		fmt.Printf("File Type:   ✅ Enabled\n")
		fmt.Printf("  Spoofing:  %v\n", cfg.FileType.DetectSpoofing)
		fmt.Println()
	} else {
		fmt.Println("File Type:   ❌ Disabled")
		fmt.Println()
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("✅ DarkScan is operational")
}

func buildStatusJSON(scanner *darkscan.Client, cfg *darkscan.Config, ctx stdcontext.Context) map[string]interface{} {
	status := make(map[string]interface{})

	// Connection
	connStatus := scanner.GetConnectionStatus()
	status["connection"] = map[string]interface{}{
		"mode":             connStatus.Mode,
		"daemon_connected": connStatus.DaemonConnected,
	}

	// Engines
	status["engines"] = map[string]interface{}{
		"enabled": scanner.GetEnabledEngines(),
		"count":   scanner.GetEngineCount(),
	}

	// Quarantine
	if cfg.Quarantine.Enabled {
		quarantineList, err := scanner.ListQuarantine(ctx)
		quarantineInfo := map[string]interface{}{
			"enabled":   true,
			"path":      cfg.Quarantine.Path,
			"encrypted": cfg.Quarantine.Encrypt,
		}
		if err == nil {
			quarantineInfo["file_count"] = len(quarantineList)
		}
		status["quarantine"] = quarantineInfo
	} else {
		status["quarantine"] = map[string]interface{}{"enabled": false}
	}

	// Hash Store
	if cfg.HashStore.Enabled {
		filter := darkscan.HistoryFilter{Limit: 1000}
		history, _ := scanner.GetScanHistory(ctx, filter)
		infected := 0
		for _, entry := range history {
			if entry.Infected {
				infected++
			}
		}
		status["hash_store"] = map[string]interface{}{
			"enabled":       true,
			"total_scans":   len(history),
			"infected":      infected,
			"clean":         len(history) - infected,
			"retention_days": cfg.HashStore.RetentionDays,
		}
	} else {
		status["hash_store"] = map[string]interface{}{"enabled": false}
	}

	// Privacy
	status["privacy"] = map[string]interface{}{
		"enabled":        cfg.Privacy.Enabled,
		"browsers":       cfg.Privacy.ScanBrowsers,
		"block_trackers": cfg.Privacy.BlockTrackers,
	}

	// Rules
	if cfg.RuleManager.Enabled {
		ruleInfo, _ := scanner.GetRuleInfo()
		status["rules"] = map[string]interface{}{
			"enabled":     true,
			"total_rules": ruleInfo.TotalRules,
			"repos":       len(ruleInfo.Repositories),
			"auto_update": cfg.RuleManager.AutoUpdate,
			"last_update": ruleInfo.LastUpdate,
		}
	} else {
		status["rules"] = map[string]interface{}{"enabled": false}
	}

	// Profiles
	if cfg.Profiles.Enabled {
		profiles, _ := scanner.ListProfiles()
		status["profiles"] = map[string]interface{}{
			"enabled":         true,
			"count":           len(profiles),
			"default_profile": cfg.Profiles.DefaultProfile,
		}
	} else {
		status["profiles"] = map[string]interface{}{"enabled": false}
	}

	// File Type
	status["file_type"] = map[string]interface{}{
		"enabled":         cfg.FileType.Enabled,
		"detect_spoofing": cfg.FileType.DetectSpoofing,
	}

	return status
}

func init() {
	darkscanCmd.AddCommand(darkscanStatusCmd)
}
