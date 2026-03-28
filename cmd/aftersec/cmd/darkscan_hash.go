package cmd

import (
	stdcontext "context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var (
	hashQuery      string
	hashCheckValue string
	hashExportFile string
	hashExportFormat string
	hashPruneOlder string
	hashInfectedOnly bool
)

var darkscanHashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Manage hash store and scan cache",
	Long: `Manage the DarkScan hash store for scan deduplication and history.

The hash store maintains a database of file hashes with scan results,
enabling:
  • Fast scan result lookups
  • Scan deduplication (avoid rescanning identical files)
  • Historical tracking of scan results
  • Cache statistics and analytics

Examples:
  aftersec darkscan hash stats
  aftersec darkscan hash check --hash abc123...
  aftersec darkscan hash search --query malware
  aftersec darkscan hash export --format csv --output hashes.csv
  aftersec darkscan hash prune --older-than 30d`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'aftersec darkscan hash --help' to see available commands")
	},
}

var hashStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show hash store statistics",
	Long: `Display statistics about the hash store database.

Shows:
  • Total number of hashes
  • Clean vs infected file counts
  • Cache hit rate estimates
  • Database size
  • Last update time

Examples:
  aftersec darkscan hash stats
  aftersec darkscan hash stats --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		showHashStats(scanner, ctx)
	},
}

var hashCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a hash exists in the store",
	Long: `Look up a file hash in the hash store.

Returns:
  • Whether the hash exists
  • Scan result (clean/infected)
  • Detected threats
  • First and last seen times
  • Scan count

Examples:
  aftersec darkscan hash check --hash abc123def456...
  aftersec darkscan hash check --hash abc123def456 --json`,
	Run: func(cmd *cobra.Command, args []string) {
		if hashCheckValue == "" {
			fmt.Println("❌ Hash value required. Use --hash flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 10*time.Second)
		defer cancel()

		checkHash(scanner, ctx)
	},
}

var hashSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search hash store by file path or hash",
	Long: `Search the hash store for matching entries.

Searches both file paths and hash values, returning all matches.

Examples:
  aftersec darkscan hash search --query malware
  aftersec darkscan hash search --query "/suspicious/path"
  aftersec darkscan hash search --query abc123 --json`,
	Run: func(cmd *cobra.Command, args []string) {
		if hashQuery == "" {
			fmt.Println("❌ Search query required. Use --query flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		searchHashes(scanner, ctx)
	},
}

var hashExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export hash store to file",
	Long: `Export the entire hash store database to a file.

Supported formats:
  • json - JSON format (structured data)
  • csv  - CSV format (spreadsheet)

Examples:
  aftersec darkscan hash export --format csv --output hashes.csv
  aftersec darkscan hash export --format json --output hashes.json --infected-only`,
	Run: func(cmd *cobra.Command, args []string) {
		if hashExportFile == "" {
			fmt.Println("❌ Output file required. Use --output flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
		defer cancel()

		exportHashes(scanner, ctx)
	},
}

var hashPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Remove old entries from hash store",
	Long: `Delete hash store entries older than a specified duration.

Duration format:
  • 7d   - 7 days
  • 30d  - 30 days (recommended)
  • 90d  - 90 days
  • 1y   - 1 year

This helps manage database size by removing outdated scan results.

Examples:
  aftersec darkscan hash prune --older-than 30d
  aftersec darkscan hash prune --older-than 90d --json`,
	Run: func(cmd *cobra.Command, args []string) {
		if hashPruneOlder == "" {
			fmt.Println("❌ Duration required. Use --older-than flag (e.g., 30d)")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 1*time.Minute)
		defer cancel()

		pruneHashes(scanner, ctx)
	},
}

func showHashStats(scanner *darkscan.Client, ctx stdcontext.Context) {
	filter := darkscan.HistoryFilter{
		Limit: 100000, // Get all entries for stats
	}

	history, err := scanner.GetScanHistory(ctx, filter)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to get hash store stats: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to get hash store stats: %v\n", err)
		}
		os.Exit(1)
	}

	// Calculate statistics
	totalHashes := len(history)
	infected := 0
	clean := 0
	totalScans := 0

	for _, entry := range history {
		totalScans += entry.ScanCount
		if entry.Infected {
			infected++
		} else {
			clean++
		}
	}

	cacheHitRate := 0.0
	if totalScans > totalHashes && totalHashes > 0 {
		cacheHitRate = float64(totalScans-totalHashes) / float64(totalScans) * 100
	}

	stats := map[string]interface{}{
		"total_hashes":   totalHashes,
		"infected":       infected,
		"clean":          clean,
		"total_scans":    totalScans,
		"cache_hit_rate": fmt.Sprintf("%.1f%%", cacheHitRate),
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    stats,
		})
		return
	}

	printHashStats(stats, history)
}

func checkHash(scanner *darkscan.Client, ctx stdcontext.Context) {
	entry, err := scanner.CheckHash(ctx, hashCheckValue)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Hash lookup failed: %v", err),
			})
		} else {
			fmt.Printf("❌ Hash lookup failed: %v\n", err)
		}
		os.Exit(1)
	}

	if entry == nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: true,
				Data: map[string]interface{}{
					"found": false,
					"hash":  hashCheckValue,
				},
			})
		} else {
			fmt.Printf("❌ Hash not found in database: %s\n", hashCheckValue)
		}
		return
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data: map[string]interface{}{
				"found": true,
				"entry": entry,
			},
		})
		return
	}

	printHashEntry(entry)
}

func searchHashes(scanner *darkscan.Client, ctx stdcontext.Context) {
	results, err := scanner.SearchHistory(ctx, hashQuery)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Search failed: %v", err),
			})
		} else {
			fmt.Printf("❌ Search failed: %v\n", err)
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

	printHashSearchResults(results, hashQuery)
}

func exportHashes(scanner *darkscan.Client, ctx stdcontext.Context) {
	filter := darkscan.HistoryFilter{
		Limit: 100000,
	}

	if hashInfectedOnly {
		infected := true
		filter.Infected = &infected
	}

	history, err := scanner.GetScanHistory(ctx, filter)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to retrieve hash data: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to retrieve hash data: %v\n", err)
		}
		os.Exit(1)
	}

	format := strings.ToLower(hashExportFormat)
	if format != "json" && format != "csv" {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   "Unsupported format. Use 'json' or 'csv'",
			})
		} else {
			fmt.Println("❌ Unsupported format. Use 'json' or 'csv'")
		}
		os.Exit(1)
	}

	file, err := os.Create(hashExportFile)
	if err != nil {
		fmt.Printf("❌ Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	if format == "json" {
		err = exportHashesToJSON(file, history)
	} else {
		err = exportHashesToCSV(file, history)
	}

	if err != nil {
		fmt.Printf("❌ Export failed: %v\n", err)
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Exported %d entries to %s", len(history), hashExportFile),
		})
	} else {
		fmt.Printf("✅ Exported %d entries to %s (%s format)\n",
			len(history), hashExportFile, format)
	}
}

func pruneHashes(scanner *darkscan.Client, ctx stdcontext.Context) {
	duration, err := parseDuration(hashPruneOlder)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Invalid duration: %v", err),
			})
		} else {
			fmt.Printf("❌ Invalid duration: %v\n", err)
			fmt.Println("Use format like: 7d, 30d, 90d, 1y")
		}
		os.Exit(1)
	}

	if outputFormat != "json" {
		fmt.Printf("Pruning entries older than %s...\n", hashPruneOlder)
	}

	count, err := scanner.PruneHashStore(ctx, duration)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Prune failed: %v", err),
			})
		} else {
			fmt.Printf("❌ Prune failed: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data: map[string]interface{}{
				"entries_removed": count,
				"cutoff_duration": hashPruneOlder,
			},
		})
	} else {
		fmt.Printf("✅ Removed %d entries from hash store\n", count)
	}
}

func printHashStats(stats map[string]interface{}, history []*darkscan.HashEntry) {
	fmt.Println("📊 Hash Store Statistics")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Total Hashes:    %v\n", stats["total_hashes"])
	fmt.Printf("Infected Files:  %v\n", stats["infected"])
	fmt.Printf("Clean Files:     %v\n", stats["clean"])
	fmt.Printf("Total Scans:     %v\n", stats["total_scans"])
	fmt.Printf("Cache Hit Rate:  %v\n", stats["cache_hit_rate"])

	if len(history) > 0 {
		newest := history[0]
		oldest := history[len(history)-1]
		fmt.Printf("\nNewest Entry:    %s\n", newest.LastSeen.Format("2006-01-02 15:04:05"))
		fmt.Printf("Oldest Entry:    %s\n", oldest.FirstSeen.Format("2006-01-02 15:04:05"))
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printHashEntry(entry *darkscan.HashEntry) {
	status := "✅ CLEAN"
	if entry.Infected {
		status = "🔴 INFECTED"
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Hash:         %s\n", entry.Hash)
	fmt.Printf("Status:       %s\n", status)
	fmt.Printf("File Path:    %s\n", entry.FilePath)
	fmt.Printf("First Seen:   %s\n", entry.FirstSeen.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Seen:    %s\n", entry.LastSeen.Format("2006-01-02 15:04:05"))
	fmt.Printf("Scan Count:   %d\n", entry.ScanCount)

	if entry.Infected && len(entry.Threats) > 0 {
		fmt.Println("\nThreats Detected:")
		for _, threat := range entry.Threats {
			fmt.Printf("  • [%s] %s (%s)\n", threat.Engine, threat.Name, threat.Severity)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printHashSearchResults(results []*darkscan.HashEntry, query string) {
	fmt.Printf("🔍 Search Results for: %s\n", query)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(results) == 0 {
		fmt.Println("No results found")
		return
	}

	fmt.Printf("Found %d result(s)\n\n", len(results))

	for i, entry := range results {
		status := "✅"
		if entry.Infected {
			status = "🔴"
		}

		fmt.Printf("%d. %s %s\n", i+1, status, truncatePath(entry.FilePath, 70))
		fmt.Printf("   Hash: %s...%s\n", entry.Hash[:12], entry.Hash[len(entry.Hash)-12:])
		fmt.Printf("   Last Seen: %s\n", entry.LastSeen.Format("2006-01-02 15:04:05"))

		if entry.Infected {
			fmt.Printf("   Threats: %d\n", len(entry.Threats))
		}

		fmt.Println()
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func exportHashesToJSON(file *os.File, history []*darkscan.HashEntry) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(history)
}

func exportHashesToCSV(file *os.File, history []*darkscan.HashEntry) error {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Hash",
		"FilePath",
		"FirstSeen",
		"LastSeen",
		"ScanCount",
		"Infected",
		"ThreatCount",
		"ThreatNames",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data
	for _, entry := range history {
		infected := "false"
		if entry.Infected {
			infected = "true"
		}

		threatNames := ""
		for i, threat := range entry.Threats {
			if i > 0 {
				threatNames += "; "
			}
			threatNames += fmt.Sprintf("%s (%s)", threat.Name, threat.Engine)
		}

		record := []string{
			entry.Hash,
			entry.FilePath,
			entry.FirstSeen.Format(time.RFC3339),
			entry.LastSeen.Format(time.RFC3339),
			fmt.Sprintf("%d", entry.ScanCount),
			infected,
			fmt.Sprintf("%d", len(entry.Threats)),
			threatNames,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	// Support simple format: 7d, 30d, 90d, 1y
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration format")
	}

	unit := s[len(s)-1]
	valueStr := s[:len(s)-1]

	var value int
	_, err := fmt.Sscanf(valueStr, "%d", &value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", valueStr)
	}

	switch unit {
	case 'd', 'D':
		return time.Duration(value) * 24 * time.Hour, nil
	case 'w', 'W':
		return time.Duration(value) * 7 * 24 * time.Hour, nil
	case 'm', 'M':
		return time.Duration(value) * 30 * 24 * time.Hour, nil
	case 'y', 'Y':
		return time.Duration(value) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid duration unit: %c (use d, w, m, y)", unit)
	}
}

func init() {
	darkscanCmd.AddCommand(darkscanHashCmd)

	// Subcommands
	darkscanHashCmd.AddCommand(hashStatsCmd)
	darkscanHashCmd.AddCommand(hashCheckCmd)
	darkscanHashCmd.AddCommand(hashSearchCmd)
	darkscanHashCmd.AddCommand(hashExportCmd)
	darkscanHashCmd.AddCommand(hashPruneCmd)

	// Check flags
	hashCheckCmd.Flags().StringVar(&hashCheckValue, "hash", "", "Hash value to check (required)")
	hashCheckCmd.MarkFlagRequired("hash")

	// Search flags
	hashSearchCmd.Flags().StringVarP(&hashQuery, "query", "q", "", "Search query (required)")
	hashSearchCmd.MarkFlagRequired("query")

	// Export flags
	hashExportCmd.Flags().StringVarP(&hashExportFormat, "format", "f", "json", "Export format (json, csv)")
	hashExportCmd.Flags().StringVarP(&hashExportFile, "output", "o", "", "Output file (required)")
	hashExportCmd.Flags().BoolVar(&hashInfectedOnly, "infected-only", false, "Export only infected files")
	hashExportCmd.MarkFlagRequired("output")

	// Prune flags
	hashPruneCmd.Flags().StringVar(&hashPruneOlder, "older-than", "", "Duration (e.g., 30d, 90d, 1y)")
	hashPruneCmd.MarkFlagRequired("older-than")
}
