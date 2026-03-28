package cmd

import (
	stdcontext "context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/client"
	"aftersec/pkg/darkscan"
)

var (
	exportFormat     string
	exportOutputFile string
	exportLimit      int
	exportInfectedOnly bool
)

var darkscanExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan results and generate reports",
	Long: `Export malware scan history and results to various formats:

Supported formats:
  - json    JSON format (structured data)
  - csv     CSV format (spreadsheet)
  - xml     XML format (enterprise integration)
  - text    Plain text format (human-readable)

Examples:
  aftersec darkscan export --format json --output results.json
  aftersec darkscan export --format csv --output report.csv --limit 100
  aftersec darkscan export --format xml --infected-only`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfigForExport()
		scanner := initDarkScanClientForExport(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
		defer cancel()

		exportScanHistory(scanner, ctx)
	},
}

func loadDarkScanConfigForExport() *darkscan.Config {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("❌ Failed to get home directory: %v\n", err)
		os.Exit(1)
	}

	configPath := filepath.Join(home, ".aftersec", "config.yaml")
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Daemon.DarkScan.Enabled {
		fmt.Println("❌ DarkScan is disabled")
		fmt.Println("Enable it in ~/.aftersec/config.yaml under daemon.darkscan.enabled: true")
		os.Exit(1)
	}

	return &cfg.Daemon.DarkScan
}

func initDarkScanClientForExport(cfg *darkscan.Config) *darkscan.Client {
	scanner, err := darkscan.NewClient(cfg)
	if err != nil {
		fmt.Printf("❌ Failed to initialize DarkScan: %v\n", err)
		os.Exit(1)
	}
	return scanner
}

func exportScanHistory(scanner *darkscan.Client, ctx stdcontext.Context) {
	// Validate format
	format := strings.ToLower(exportFormat)
	if format != "json" && format != "csv" && format != "xml" && format != "text" {
		fmt.Printf("❌ Unsupported export format: %s\n", exportFormat)
		fmt.Println("Supported formats: json, csv, xml, text")
		os.Exit(1)
	}

	// Fetch scan history
	filter := darkscan.HistoryFilter{
		Limit: exportLimit,
	}

	history, err := scanner.GetScanHistory(ctx, filter)
	if err != nil {
		fmt.Printf("❌ Failed to retrieve scan history: %v\n", err)
		os.Exit(1)
	}

	// Filter infected only if requested
	var filteredHistory []*darkscan.HashEntry
	if exportInfectedOnly {
		for _, entry := range history {
			if entry.Infected {
				filteredHistory = append(filteredHistory, entry)
			}
		}
	} else {
		filteredHistory = history
	}

	if len(filteredHistory) == 0 {
		fmt.Println("⚠️  No scan results to export")
		return
	}

	// Build report
	report := buildExportReport(filteredHistory)

	// Export to file or stdout
	var output *os.File
	if exportOutputFile != "" && format != "text" {
		output, err = os.Create(exportOutputFile)
		if err != nil {
			fmt.Printf("❌ Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Export in specified format
	switch format {
	case "json":
		err = exportToJSON(output, report)
	case "csv":
		err = exportToCSV(output, report)
	case "xml":
		err = exportToXML(output, report)
	case "text":
		err = exportToText(output, report)
	}

	if err != nil {
		fmt.Printf("❌ Export failed: %v\n", err)
		os.Exit(1)
	}

	if exportOutputFile != "" && format != "text" {
		fmt.Printf("✅ Exported %d scan result(s) to %s (%s format)\n",
			len(filteredHistory), exportOutputFile, format)
	}
}

// ExportReport wraps scan history with metadata
type ExportReport struct {
	XMLName      xml.Name `xml:"DarkScanReport" json:"-"`
	Summary      ExportSummary
	Results      []ExportResult
	GeneratedAt  time.Time
	TotalScans   int
	ExportFormat string
}

// ExportSummary provides aggregate statistics
type ExportSummary struct {
	XMLName       xml.Name `xml:"Summary" json:"-"`
	TotalScans    int      `xml:"TotalScans" json:"total_scans"`
	InfectedFiles int      `xml:"InfectedFiles" json:"infected_files"`
	CleanFiles    int      `xml:"CleanFiles" json:"clean_files"`
	UniqueThreats int      `xml:"UniqueThreats" json:"unique_threats"`
}

// ExportResult is a serialization-friendly version of HashEntry
type ExportResult struct {
	XMLName      xml.Name      `xml:"ScanResult" json:"-"`
	FilePath     string        `xml:"FilePath" json:"file_path" csv:"FilePath"`
	FileHash     string        `xml:"FileHash" json:"file_hash" csv:"FileHash"`
	Infected     bool          `xml:"Infected" json:"infected" csv:"Infected"`
	Threats      []ExportThreat `xml:"Threats>Threat" json:"threats"`
	ScanDate     time.Time     `xml:"ScanDate" json:"scan_date" csv:"ScanDate"`
	EnginesUsed  string        `xml:"EnginesUsed" json:"engines_used" csv:"EnginesUsed"`
	ScanDuration string        `xml:"ScanDuration" json:"scan_duration" csv:"ScanDuration"`
}

// ExportThreat represents a detected threat
type ExportThreat struct {
	XMLName     xml.Name `xml:"Threat" json:"-"`
	Name        string   `xml:"Name" json:"name"`
	Severity    string   `xml:"Severity" json:"severity"`
	Engine      string   `xml:"Engine" json:"engine"`
	Description string   `xml:"Description,omitempty" json:"description,omitempty"`
}

func buildExportReport(history []*darkscan.HashEntry) ExportReport {
	report := ExportReport{
		GeneratedAt:  time.Now(),
		TotalScans:   len(history),
		ExportFormat: exportFormat,
		Results:      make([]ExportResult, 0, len(history)),
	}

	uniqueThreats := make(map[string]bool)

	for _, entry := range history {
		result := ExportResult{
			FilePath:     entry.FilePath,
			FileHash:     entry.Hash,
			Infected:     entry.Infected,
			ScanDate:     entry.LastSeen,
			EnginesUsed:  "", // HashEntry doesn't store engines used
			ScanDuration: "", // HashEntry doesn't store scan duration
			Threats:      make([]ExportThreat, 0, len(entry.Threats)),
		}

		for _, threat := range entry.Threats {
			result.Threats = append(result.Threats, ExportThreat{
				Name:        threat.Name,
				Severity:    threat.Severity,
				Engine:      threat.Engine,
				Description: threat.Description,
			})
			uniqueThreats[threat.Name] = true
		}

		report.Results = append(report.Results, result)

		if entry.Infected {
			report.Summary.InfectedFiles++
		} else {
			report.Summary.CleanFiles++
		}
	}

	report.Summary.TotalScans = len(history)
	report.Summary.UniqueThreats = len(uniqueThreats)

	return report
}

func exportToJSON(output *os.File, report ExportReport) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func exportToCSV(output *os.File, report ExportReport) error {
	writer := csv.NewWriter(output)
	defer writer.Flush()

	// Write header
	header := []string{
		"FilePath",
		"FileHash",
		"Infected",
		"ThreatCount",
		"ThreatNames",
		"Engines",
		"ScanDate",
		"Duration",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data
	for _, result := range report.Results {
		infected := "false"
		if result.Infected {
			infected = "true"
		}

		// Concatenate threat names
		threatNames := ""
		for i, threat := range result.Threats {
			if i > 0 {
				threatNames += "; "
			}
			threatNames += fmt.Sprintf("%s (%s/%s)", threat.Name, threat.Engine, threat.Severity)
		}

		record := []string{
			result.FilePath,
			result.FileHash,
			infected,
			fmt.Sprintf("%d", len(result.Threats)),
			threatNames,
			result.EnginesUsed,
			result.ScanDate.Format(time.RFC3339),
			result.ScanDuration,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportToXML(output *os.File, report ExportReport) error {
	encoder := xml.NewEncoder(output)
	encoder.Indent("", "  ")

	// Write XML header
	if _, err := output.WriteString(xml.Header); err != nil {
		return err
	}

	return encoder.Encode(report)
}

func exportToText(output *os.File, report ExportReport) error {
	// Write header
	fmt.Fprintf(output, "DarkScan Scan Results Export\n")
	fmt.Fprintf(output, "Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Write summary
	fmt.Fprintf(output, "Summary:\n")
	fmt.Fprintf(output, "  Total Scans:    %d\n", report.Summary.TotalScans)
	fmt.Fprintf(output, "  Infected Files: %d\n", report.Summary.InfectedFiles)
	fmt.Fprintf(output, "  Clean Files:    %d\n", report.Summary.CleanFiles)
	fmt.Fprintf(output, "  Unique Threats: %d\n\n", report.Summary.UniqueThreats)

	// Write results
	fmt.Fprintf(output, "Scan Results:\n")
	fmt.Fprintf(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	for i, result := range report.Results {
		status := "✅ CLEAN"
		if result.Infected {
			status = "🔴 INFECTED"
		}

		fmt.Fprintf(output, "%d. %s\n", i+1, status)
		fmt.Fprintf(output, "   File: %s\n", result.FilePath)
		fmt.Fprintf(output, "   Hash: %s\n", result.FileHash)
		fmt.Fprintf(output, "   Date: %s\n", result.ScanDate.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(output, "   Engines: %s\n", result.EnginesUsed)
		fmt.Fprintf(output, "   Duration: %s\n", result.ScanDuration)

		if len(result.Threats) > 0 {
			fmt.Fprintf(output, "   Threats:\n")
			for _, threat := range result.Threats {
				fmt.Fprintf(output, "     • [%s] %s (%s)\n",
					threat.Engine, threat.Name, threat.Severity)
				if threat.Description != "" {
					fmt.Fprintf(output, "       %s\n", threat.Description)
				}
			}
		}

		fmt.Fprintf(output, "\n")
	}

	fmt.Fprintf(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Fprintf(output, "End of Report\n")

	return nil
}

func init() {
	darkscanCmd.AddCommand(darkscanExportCmd)

	darkscanExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json",
		"Export format (json, csv, xml, text)")
	darkscanExportCmd.Flags().StringVarP(&exportOutputFile, "output", "o", "",
		"Output file (default: stdout)")
	darkscanExportCmd.Flags().IntVarP(&exportLimit, "limit", "l", 1000,
		"Maximum number of scan results to export")
	darkscanExportCmd.Flags().BoolVar(&exportInfectedOnly, "infected-only", false,
		"Export only infected files")
}
