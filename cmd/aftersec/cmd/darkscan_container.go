package cmd

import (
	stdcontext "context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var darkscanContainerCmd = &cobra.Command{
	Use:   "container",
	Short: "Container image security scanning",
	Long: `Comprehensive security scanning of Docker/OCI container images:

• Vulnerability scanning (CVEs)
• Malware detection in layers
• Secret detection (API keys, passwords)
• Configuration security analysis

Supports: Docker images, OCI images, exported tarballs.

Integration with third-party scanners:
• Trivy (preferred)
• Grype (fallback)
• Built-in scanner (if tools unavailable)`,
}

var darkscanContainerScanCmd = &cobra.Command{
	Use:   "scan [image-reference]",
	Short: "Scan a container image",
	Long: `Scan a container image for vulnerabilities and malware.

Examples:
  aftersec darkscan container scan nginx:latest
  aftersec darkscan container scan myregistry.io/app:v1.2.3
  aftersec darkscan container scan /path/to/image.tar`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		imageRef := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")
		verbose, _ := cmd.Flags().GetBool("verbose")

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		if !jsonOutput {
			fmt.Printf("🐳 Scanning container image: %s\n", imageRef)
			fmt.Println("This may take several minutes for large images...")
			fmt.Println()
		}

		ctx := stdcontext.Background()
		result, err := scanner.ScanContainerImage(ctx, imageRef)
		if err != nil {
			if jsonOutput {
				containerOutputJSON(JSONOutput{
					Success: false,
					Error:   err.Error(),
				})
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			containerOutputJSON(JSONOutput{
				Success: true,
				Data:    result,
			})
			return
		}

		printContainerScanResult(result, verbose)
	},
}

func init() {
	darkscanCmd.AddCommand(darkscanContainerCmd)
	darkscanContainerCmd.AddCommand(darkscanContainerScanCmd)

	darkscanContainerScanCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	darkscanContainerScanCmd.Flags().BoolP("verbose", "v", false, "Show detailed analysis")
}

func printContainerScanResult(result *darkscan.ContainerScanResult, verbose bool) {
	fmt.Printf("\n📦 Container Security Scan Results\n")
	fmt.Println(strings.Repeat("═", 80))
	fmt.Printf("Image:        %s\n", result.ImageRef)
	fmt.Printf("Scanner:      %s\n", result.ScannerUsed)
	fmt.Printf("Risk Level:   %s\n", formatRiskLevel(result.RiskLevel))
	fmt.Println()

	// Summary counts
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Layers:             %d\n", len(result.Layers))
	fmt.Printf("  Vulnerabilities:    %d", len(result.Vulnerabilities))
	if len(result.Vulnerabilities) > 0 {
		critical := countBySeverity(result.Vulnerabilities, "CRITICAL")
		high := countBySeverity(result.Vulnerabilities, "HIGH")
		medium := countBySeverity(result.Vulnerabilities, "MEDIUM")
		low := countBySeverity(result.Vulnerabilities, "LOW")
		fmt.Printf(" (Critical: %d, High: %d, Medium: %d, Low: %d)", critical, high, medium, low)
	}
	fmt.Println()
	fmt.Printf("  Malware Detections: %d\n", len(result.MalwareDetected))
	fmt.Printf("  Secrets Found:      %d\n", len(result.Secrets))
	fmt.Printf("  Config Issues:      %d\n", len(result.ConfigIssues))
	fmt.Println()

	// Malware detections
	if len(result.MalwareDetected) > 0 {
		fmt.Printf("🦠 Malware Detections:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Layer\tFile\tThreat\tConfidence")
		fmt.Fprintln(w, strings.Repeat("─", 80))
		for _, malware := range result.MalwareDetected {
			fmt.Fprintf(w, "%s\t%s\t%s\t%.0f%%\n",
				truncatePath(malware.Layer, 12),
				truncatePath(malware.FilePath, 30),
				malware.ThreatName,
				malware.Confidence*100)
		}
		w.Flush()
		fmt.Println()
	}

	// Secrets found
	if len(result.Secrets) > 0 {
		fmt.Printf("🔑 Secrets Detected:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Type\tLocation\tSeverity")
		fmt.Fprintln(w, strings.Repeat("─", 80))
		for _, secret := range result.Secrets {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				secret.SecretType,
				truncatePath(secret.FilePath, 50),
				secret.Severity)
		}
		w.Flush()
		fmt.Println()
	}

	// Config issues
	if len(result.ConfigIssues) > 0 {
		fmt.Printf("⚙️  Configuration Issues:\n")
		for _, issue := range result.ConfigIssues {
			fmt.Printf("  [%s] %s: %s\n", issue.Severity, issue.Type, issue.Description)
		}
		fmt.Println()
	}

	// Vulnerabilities (top 10 or all if verbose)
	if len(result.Vulnerabilities) > 0 {
		fmt.Printf("🔍 Vulnerabilities:\n")
		vulnsToShow := result.Vulnerabilities
		if !verbose && len(vulnsToShow) > 10 {
			vulnsToShow = result.Vulnerabilities[:10]
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "CVE\tPackage\tVersion\tSeverity\tFixed")
		fmt.Fprintln(w, strings.Repeat("─", 80))
		for _, vuln := range vulnsToShow {
			fixedVersion := vuln.FixedIn
			if fixedVersion == "" {
				fixedVersion = "N/A"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				vuln.ID,
				truncatePath(vuln.Package, 25),
				vuln.Version,
				formatSeverity(vuln.Severity),
				fixedVersion)
		}
		w.Flush()

		if !verbose && len(result.Vulnerabilities) > 10 {
			fmt.Printf("\n... and %d more vulnerabilities (use --verbose to see all)\n", len(result.Vulnerabilities)-10)
		}
		fmt.Println()
	}

	// Layer information (if verbose)
	if verbose && len(result.Layers) > 0 {
		fmt.Printf("📚 Layer Details:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Digest\tSize\tCommand\tMalware")
		fmt.Fprintln(w, strings.Repeat("─", 100))
		for _, layer := range result.Layers {
			malwareStatus := "✅ Clean"
			if layer.MalwareFound {
				malwareStatus = "🦠 Infected"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				truncatePath(layer.Digest, 16),
				formatBytes(layer.Size),
				truncatePath(layer.Command, 40),
				malwareStatus)
		}
		w.Flush()
		fmt.Println()
	}

	// Final verdict
	fmt.Println(strings.Repeat("═", 80))
	switch result.RiskLevel {
	case "CRITICAL":
		fmt.Println("❌ CRITICAL RISK - This image should NOT be deployed")
	case "HIGH":
		fmt.Println("⚠️  HIGH RISK - Immediate remediation required")
	case "MEDIUM":
		fmt.Println("⚠️  MEDIUM RISK - Review and patch recommended")
	case "LOW":
		fmt.Println("✅ LOW RISK - Minor issues detected")
	default:
		fmt.Println("✅ CLEAN - No significant issues detected")
	}
	fmt.Println()
}

func formatRiskLevel(level string) string {
	switch level {
	case "CRITICAL":
		return "🔴 CRITICAL"
	case "HIGH":
		return "🟠 HIGH"
	case "MEDIUM":
		return "🟡 MEDIUM"
	case "LOW":
		return "🟢 LOW"
	default:
		return "✅ CLEAN"
	}
}

func formatSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴 CRITICAL"
	case "HIGH":
		return "🟠 HIGH"
	case "MEDIUM":
		return "🟡 MEDIUM"
	case "LOW":
		return "🟢 LOW"
	default:
		return severity
	}
}

func countBySeverity(vulns []darkscan.Vulnerability, severity string) int {
	count := 0
	for _, v := range vulns {
		if v.Severity == severity {
			count++
		}
	}
	return count
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func containerOutputJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
