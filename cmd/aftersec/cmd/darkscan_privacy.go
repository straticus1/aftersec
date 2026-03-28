package cmd

import (
	stdcontext "context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var (
	privacyBrowsers   []string
	privacyAppPath    string
	privacySeverity   string
	privacyType       string
	privacyTrackerIDs []string
	privacyDataTypes  []string
)

var darkscanPrivacyCmd = &cobra.Command{
	Use:   "privacy",
	Short: "Privacy and telemetry scanning",
	Long: `Scan browsers and applications for privacy issues:

• Browser tracking cookies
• Telemetry endpoints
• Extension permissions
• Browser hijacking
• Application data collection

Examples:
  aftersec darkscan privacy scan --browsers chrome,firefox
  aftersec darkscan privacy list --severity high
  aftersec darkscan privacy remove --browser chrome --tracker-ids abc123`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'aftersec darkscan privacy --help' to see available commands")
	},
}

var privacyScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan browsers or applications for privacy issues",
	Long: `Scan browsers for tracking cookies, telemetry, and privacy violations.

Supported browsers:
  - chrome    Google Chrome
  - firefox   Mozilla Firefox
  - safari    Apple Safari
  - brave     Brave Browser
  - edge      Microsoft Edge

Examples:
  aftersec darkscan privacy scan --browsers chrome,firefox
  aftersec darkscan privacy scan --browsers all
  aftersec darkscan privacy scan --app /Applications/Slack.app
  aftersec darkscan privacy scan --browsers chrome --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Minute)
		defer cancel()

		if privacyAppPath != "" {
			scanApplication(scanner, ctx)
			return
		}

		scanBrowsers(scanner, ctx)
	},
}

var privacyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List privacy findings from previous scans",
	Long: `List all privacy findings with optional filtering.

Filters:
  --severity    Filter by severity (low, medium, high, critical)
  --type        Filter by type (cookie, telemetry, extension, hijack)
  --browsers    Filter by browser (chrome, firefox, safari, brave, edge)

Examples:
  aftersec darkscan privacy list
  aftersec darkscan privacy list --severity high
  aftersec darkscan privacy list --type cookie --browsers chrome
  aftersec darkscan privacy list --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
		defer cancel()

		listFindings(scanner, ctx)
	},
}

var privacyRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove tracking cookies and data",
	Long: `Remove specified trackers from a browser.

Warning: This will modify browser data. Back up your profile first.

Examples:
  aftersec darkscan privacy remove --browser chrome --tracker-ids abc123,def456
  aftersec darkscan privacy remove --browser firefox --tracker-ids all`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 1*time.Minute)
		defer cancel()

		removeTrackers(scanner, ctx)
	},
}

var privacyClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear browser data (cookies, cache, history)",
	Long: `Clear specified types of browser data.

Data types:
  - cookies     HTTP cookies
  - cache       Cached files and images
  - history     Browsing history
  - passwords   Saved passwords
  - all         All data types

Warning: This operation is irreversible.

Examples:
  aftersec darkscan privacy clear --browser chrome --data cookies,cache
  aftersec darkscan privacy clear --browser firefox --data all`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("⚠️  Warning: This feature is not yet implemented in the DarkScan backend")
		fmt.Println("Coming soon: Clear browser data functionality")
	},
}

func scanBrowsers(scanner *darkscan.Client, ctx stdcontext.Context) {
	// Parse browser list
	browsers := parseBrowserList(privacyBrowsers)
	if len(browsers) == 0 {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   "No browsers specified. Use --browsers chrome,firefox,safari,brave,edge or --browsers all",
			})
		} else {
			fmt.Println("❌ No browsers specified")
			fmt.Println("Usage: --browsers chrome,firefox,safari,brave,edge")
			fmt.Println("   or: --browsers all")
		}
		os.Exit(1)
	}

	if outputFormat != "json" {
		fmt.Printf("🔍 Scanning %d browser(s) for privacy issues...\n\n", len(browsers))
	}

	results, err := scanner.ScanBrowserPrivacy(ctx, browsers)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Scan failed: %v", err),
			})
		} else {
			fmt.Printf("❌ Scan failed: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    results,
		})
		return
	}

	printBrowserResults(results)
}

func scanApplication(scanner *darkscan.Client, ctx stdcontext.Context) {
	if outputFormat != "json" {
		fmt.Printf("🔍 Scanning application for telemetry: %s\n\n", privacyAppPath)
	}

	result, err := scanner.ScanApplicationTelemetry(ctx, privacyAppPath)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Scan failed: %v", err),
			})
		} else {
			fmt.Printf("❌ Scan failed: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    result,
		})
		return
	}

	printApplicationResult(result)
}

func listFindings(scanner *darkscan.Client, ctx stdcontext.Context) {
	browsers := parseBrowserList(privacyBrowsers)
	browserFilter := ""
	if len(browsers) == 1 {
		browserFilter = browsers[0]
	}

	filters := darkscan.PrivacyFilter{
		Browser:   browserFilter,
		Type:      privacyType,
		RiskLevel: privacySeverity,
	}

	findings, err := scanner.ListPrivacyFindings(ctx, filters)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to list findings: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to list findings: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    findings,
		})
		return
	}

	printFindings(findings, filters)
}

func removeTrackers(scanner *darkscan.Client, ctx stdcontext.Context) {
	browsers := parseBrowserList(privacyBrowsers)
	if len(browsers) != 1 {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   "Specify exactly one browser with --browsers",
			})
		} else {
			fmt.Println("❌ Specify exactly one browser with --browsers")
		}
		os.Exit(1)
	}

	if len(privacyTrackerIDs) == 0 {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   "No tracker IDs specified. Use --tracker-ids",
			})
		} else {
			fmt.Println("❌ No tracker IDs specified")
			fmt.Println("Usage: --tracker-ids id1,id2,id3")
		}
		os.Exit(1)
	}

	browser := browsers[0]

	if outputFormat != "json" {
		fmt.Printf("🗑️  Removing %d tracker(s) from %s...\n", len(privacyTrackerIDs), browser)
	}

	err := scanner.RemoveTrackers(ctx, browser, privacyTrackerIDs)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove trackers: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to remove trackers: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Removed %d trackers from %s", len(privacyTrackerIDs), browser),
		})
	} else {
		fmt.Printf("✅ Successfully removed %d tracker(s)\n", len(privacyTrackerIDs))
	}
}

func parseBrowserList(browserFlags []string) []string {
	if len(browserFlags) == 0 {
		return []string{}
	}

	var browsers []string
	for _, flag := range browserFlags {
		for _, browser := range strings.Split(flag, ",") {
			browser = strings.TrimSpace(strings.ToLower(browser))
			if browser == "all" {
				return []string{"chrome", "firefox", "safari", "brave", "edge"}
			}
			if browser != "" {
				browsers = append(browsers, browser)
			}
		}
	}

	return browsers
}

func printBrowserResults(results []*darkscan.PrivacyScanResult) {
	totalTrackers := 0
	totalTelemetry := 0

	for _, result := range results {
		totalTrackers += len(result.TrackersFound)
		totalTelemetry += len(result.TelemetryURLs)

		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("Browser: %s\n", strings.Title(result.Browser))
		fmt.Printf("Profile: %s\n", truncatePath(result.ProfilePath, 60))
		fmt.Printf("Risk Level: %s\n", getRiskEmoji(result.RiskLevel))
		fmt.Printf("Scan Duration: %v\n\n", result.ScanDuration)

		if len(result.TrackersFound) > 0 {
			fmt.Printf("🍪 Trackers Found (%d):\n", len(result.TrackersFound))
			for _, tracker := range result.TrackersFound {
				severity := getSeverityEmoji(tracker.Severity)
				fmt.Printf("  %s [%s] %s\n", severity, tracker.Type, tracker.Name)
				fmt.Printf("     %s\n", tracker.Description)
				if tracker.Domain != "" {
					fmt.Printf("     Domain: %s\n", tracker.Domain)
				}
			}
			fmt.Println()
		} else {
			fmt.Println("✅ No trackers found\n")
		}

		if len(result.TelemetryURLs) > 0 {
			fmt.Printf("📡 Telemetry Endpoints (%d):\n", len(result.TelemetryURLs))
			for _, url := range result.TelemetryURLs {
				fmt.Printf("  • %s\n", url)
			}
			fmt.Println()
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Summary:\n")
	fmt.Printf("  Browsers Scanned: %d\n", len(results))
	fmt.Printf("  Total Trackers:   %d\n", totalTrackers)
	fmt.Printf("  Total Telemetry:  %d endpoints\n", totalTelemetry)
}

func printApplicationResult(result *darkscan.PrivacyScanResult) {
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Application: %s\n", filepath.Base(result.ProfilePath))
	fmt.Printf("Path: %s\n", result.ProfilePath)
	fmt.Printf("Risk Level: %s\n", getRiskEmoji(result.RiskLevel))
	fmt.Printf("Scan Duration: %v\n\n", result.ScanDuration)

	if len(result.TrackersFound) > 0 {
		fmt.Printf("📡 Telemetry Libraries Found (%d):\n", len(result.TrackersFound))
		for _, finding := range result.TrackersFound {
			severity := getSeverityEmoji(finding.Severity)
			fmt.Printf("  %s %s\n", severity, finding.Name)
			fmt.Printf("     %s\n", finding.Description)
			if finding.Data != "" {
				fmt.Printf("     Location: %s\n", finding.Data)
			}
		}
	} else {
		fmt.Println("✅ No telemetry libraries detected")
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printFindings(findings []*darkscan.PrivacyFinding, filters darkscan.PrivacyFilter) {
	if len(findings) == 0 {
		fmt.Println("✅ No privacy findings match the specified filters")
		return
	}

	fmt.Printf("🔍 Found %d privacy issue(s)\n", len(findings))
	if filters.Browser != "" || filters.Type != "" || filters.RiskLevel != "" {
		fmt.Printf("Filters: Browser=%s Type=%s Severity=%s\n", filters.Browser, filters.Type, filters.RiskLevel)
	}
	fmt.Println()

	for i, finding := range findings {
		severity := getSeverityEmoji(finding.Severity)
		fmt.Printf("━━━ Finding #%d ━━━\n", i+1)
		fmt.Printf("ID:          %s\n", finding.ID)
		fmt.Printf("Severity:    %s %s\n", severity, strings.ToUpper(finding.Severity))
		fmt.Printf("Type:        %s\n", finding.Type)
		fmt.Printf("Name:        %s\n", finding.Name)
		fmt.Printf("Description: %s\n", finding.Description)
		if finding.Domain != "" {
			fmt.Printf("Domain:      %s\n", finding.Domain)
		}
		fmt.Printf("Removable:   %v\n", finding.Removable)
		fmt.Println()
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Total: %d finding(s)\n", len(findings))
}

func getRiskEmoji(risk string) string {
	switch strings.ToLower(risk) {
	case "low":
		return "🟢 LOW"
	case "medium":
		return "🟡 MEDIUM"
	case "high":
		return "🟠 HIGH"
	case "critical":
		return "🔴 CRITICAL"
	default:
		return "⚪ " + strings.ToUpper(risk)
	}
}

func getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "low":
		return "🔵"
	case "medium":
		return "🟡"
	case "high":
		return "🟠"
	case "critical":
		return "🔴"
	default:
		return "⚪"
	}
}

func init() {
	darkscanCmd.AddCommand(darkscanPrivacyCmd)

	// Subcommands
	darkscanPrivacyCmd.AddCommand(privacyScanCmd)
	darkscanPrivacyCmd.AddCommand(privacyListCmd)
	darkscanPrivacyCmd.AddCommand(privacyRemoveCmd)
	darkscanPrivacyCmd.AddCommand(privacyClearCmd)

	// Scan flags
	privacyScanCmd.Flags().StringSliceVar(&privacyBrowsers, "browsers", []string{}, "Browsers to scan (chrome,firefox,safari,brave,edge,all)")
	privacyScanCmd.Flags().StringVar(&privacyAppPath, "app", "", "Application path to scan for telemetry")

	// List flags
	privacyListCmd.Flags().StringSliceVar(&privacyBrowsers, "browsers", []string{}, "Filter by browser")
	privacyListCmd.Flags().StringVar(&privacySeverity, "severity", "", "Filter by severity (low,medium,high,critical)")
	privacyListCmd.Flags().StringVar(&privacyType, "type", "", "Filter by type (cookie,telemetry,extension,hijack)")

	// Remove flags
	privacyRemoveCmd.Flags().StringSliceVar(&privacyBrowsers, "browsers", []string{}, "Browser to remove trackers from (specify one)")
	privacyRemoveCmd.Flags().StringSliceVar(&privacyTrackerIDs, "tracker-ids", []string{}, "Tracker IDs to remove (comma-separated)")
	privacyRemoveCmd.MarkFlagRequired("browsers")
	privacyRemoveCmd.MarkFlagRequired("tracker-ids")

	// Clear flags
	privacyClearCmd.Flags().StringSliceVar(&privacyBrowsers, "browsers", []string{}, "Browser to clear data from (specify one)")
	privacyClearCmd.Flags().StringSliceVar(&privacyDataTypes, "data", []string{}, "Data types to clear (cookies,cache,history,passwords,all)")
	privacyClearCmd.MarkFlagRequired("browsers")
	privacyClearCmd.MarkFlagRequired("data")
}
