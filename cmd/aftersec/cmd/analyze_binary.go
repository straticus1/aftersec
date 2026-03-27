package cmd

import (
	stdcontext "context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/ai"
	"aftersec/pkg/client"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/forensics"
	"aftersec/pkg/threatintel"
	dsforensics "github.com/afterdarktech/darkscan/pkg/forensics"
)

var (
	skipThreatIntel bool
	skipAI          bool
	skipDarkScan    bool
	verbose         bool
)

var analyzeBinaryCmd = &cobra.Command{
	Use:   "analyze-binary [BINARY_PATH]",
	Short: "Deep binary analysis with hashing, signature verification, and threat intelligence",
	Long: `Performs comprehensive binary analysis including:
  • Multi-hash computation (MD5, SHA1, SHA256)
  • Code signature verification
  • Mach-O structure & entropy analysis
  • Capability extraction & risk scoring
  • Threat intelligence lookup (FileHashes.io, DarkAPI.io)
  • String extraction with IOC detection
  • AI-powered threat analysis

Example:
  aftersec analyze-binary /Applications/Suspicious.app/Contents/MacOS/binary
  aftersec analyze-binary --skip-ai malware.bin`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		binaryPath := args[0]

		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			fmt.Printf("❌ Binary not found: %s\n", binaryPath)
			os.Exit(1)
		}

		fmt.Printf("🔍 AfterSec Advanced Binary Analysis\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("Target: %s\n\n", binaryPath)

		// Phase 1: File Hashing
		fmt.Println("📊 Phase 1: Cryptographic Hashing")
		hashes, err := calculateHashes(binaryPath)
		if err != nil {
			fmt.Printf("❌ Failed to calculate hashes: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  MD5:    %s\n", hashes.MD5)
		fmt.Printf("  SHA1:   %s\n", hashes.SHA1)
		fmt.Printf("  SHA256: %s\n\n", hashes.SHA256)

		// Phase 2: Code Signature Verification
		fmt.Println("✍️  Phase 2: Code Signature Verification")
		sigInfo := verifyCodeSignature(binaryPath)
		fmt.Println(sigInfo)

		// Phase 3: Mach-O Analysis & Capability Extraction
		fmt.Println("🔬 Phase 3: Mach-O Structure & Capability Analysis")
		var capReport *forensics.CapabilitiesReport
		if strings.HasSuffix(binaryPath, ".app") || strings.Contains(binaryPath, ".app/") {
			capReport, err = forensics.AnalyzePath(binaryPath)
		} else {
			capReport, err = forensics.AnalyzeBinary(binaryPath)
		}

		if err != nil {
			fmt.Printf("  ⚠️  Mach-O parsing failed: %v\n\n", err)
		} else {
			printCapabilityReport(capReport)
		}

		// Phase 3.5: DarkScan Deep Forensics & Heuristics
		fmt.Println("🧬 Phase 3.5: DarkScan Deep Forensics & Heuristics")
		dsAnalyzer := dsforensics.NewAnalyzer(100)
		feats, err := dsAnalyzer.Analyze(binaryPath)
		if err != nil {
			fmt.Printf("  ⚠️  DarkScan forensics failed: %v\n\n", err)
		} else {
			score := 0
			var behaviors []string
			if feats.Entropy > 7.0 {
				score += 30
				behaviors = append(behaviors, "High Entropy (Potential Packing/Encryption)")
			}
			if feats.HasInjection {
				score += 40
				behaviors = append(behaviors, "Process Injection API usage [T1055]")
			}
			if feats.HasEvasion {
				score += 20
				behaviors = append(behaviors, "Sandbox/Debug evasion API usage [T1497]")
			}
			if feats.HasExecutableStack {
				score += 50
				behaviors = append(behaviors, "Executable Stack detected (Exploitation artifact)")
			}
			if feats.HasNetworkCalls {
				behaviors = append(behaviors, "Network Communication APIs [T1043]")
				score += 10
			}
			if feats.HasPersistence {
				behaviors = append(behaviors, "Persistence Mechanisms [T1547]")
				score += 20
			}
			if feats.HasCrypto {
				behaviors = append(behaviors, "Cryptographic API usage (Ransomware/C2) [T1486]")
				score += 10
			}

			if score > 100 {
				score = 100
			}

			riskEmoji := "🟢"
			if score >= 60 {
				riskEmoji = "🔴"
			} else if score >= 30 {
				riskEmoji = "🟡"
			}

			fmt.Printf("  Heuristic Risk Score: %s %d/100\n", riskEmoji, score)
			if len(behaviors) > 0 {
				fmt.Printf("  MITRE ATT&CK Mapped Behaviors (%d):\n", len(behaviors))
				for _, b := range behaviors {
					fmt.Printf("    • %s\n", b)
				}
			} else {
				fmt.Println("  No highly suspicious heuristic behaviors detected.")
			}
			fmt.Println()
		}

		// Phase 3.7: Microscopic CPU Emulation (Unicorn)
		fmt.Println("🦄 Phase 3.7: Microscopic CPU Emulation Sandbox")
		emuCtx, emuCancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
		emuReport, err := forensics.EmulateMachO(emuCtx, binaryPath)
		emuCancel()
		
		if err != nil {
			fmt.Printf("  ⚠️  Sandbox execution aborted: %v\n\n", err)
		} else {
			fmt.Printf("  Architecture:   %s\n", emuReport.Architecture)
			fmt.Printf("  Instructions:   %d (simulated)\n", emuReport.Instructions)
			fmt.Printf("  Syscalls/Traps: %d\n", emuReport.Syscalls)
			fmt.Printf("  Unpacking Loops:%d\n", emuReport.UnpackingLoops)
			
			threatEmoji := "🟢"
			if emuReport.Score >= 50 {
				threatEmoji = "🔴"
			} else if emuReport.Score >= 20 {
				threatEmoji = "🟡"
			}
			fmt.Printf("  Heuristic Intent Score: %s %d/100\n", threatEmoji, emuReport.Score)
			if emuReport.HasError {
				fmt.Printf("  Simulation halted: %s\n", emuReport.ErrorMessage)
			}
			fmt.Println()
		}

		// Phase 4: Threat Intelligence Lookup
		if !skipThreatIntel {
			fmt.Println("🌐 Phase 4: Global Threat Intelligence")
			checkThreatIntelligence(hashes.SHA256)
		}

		// Phase 5: String Extraction & IOC Detection
		fmt.Println("🔤 Phase 5: String Extraction & IOC Detection")
		iocs := extractStringsAndIOCs(binaryPath)
		printIOCs(iocs)

		if forensics.IsFlossInstalled() {
			fmt.Println("🔍 Phase 5.5: Deep String Deobfuscation (FLOSS)")
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
			flossRes, err := forensics.ExtractFLOSS(ctx, binaryPath)
			cancel()
			if err != nil {
				fmt.Printf("  ⚠️  FLOSS analysis failed: %v\n\n", err)
			} else {
				printFlossStrings(flossRes)
			}
		} else {
			fmt.Println("🔍 Phase 5.5: Deep String Deobfuscation (FLOSS) [SKIPPED - 'floss' binary not in PATH]")
			fmt.Println()
		}

		// Phase 6: Multi-Engine Malware Scanning (DarkScan)
		if !skipDarkScan {
			fmt.Println("🛡️  Phase 6: Multi-Engine Malware Scanning")
			runDarkScan(binaryPath)
		}

		// Phase 7: AI Analysis
		if !skipAI {
			fmt.Println("🤖 Phase 7: AI-Powered Threat Analysis")
			runAIAnalysis(binaryPath, hashes, capReport, iocs)
		}

		fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("✅ Analysis Complete\n")
	},
}

type Hashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

func calculateHashes(path string) (*Hashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)
	if _, err := io.Copy(multiWriter, f); err != nil {
		return nil, err
	}

	return &Hashes{
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

func verifyCodeSignature(path string) string {
	cmd := exec.Command("codesign", "-dvvv", path)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Sprintf("  ❌ Not Signed (or verification failed)\n  %s\n", strings.TrimSpace(string(output)))
	}

	lines := strings.Split(string(output), "\n")
	var builder strings.Builder
	builder.WriteString("  ✅ Code Signature Valid\n")

	for _, line := range lines {
		if strings.Contains(line, "Authority=") ||
		   strings.Contains(line, "TeamIdentifier=") ||
		   strings.Contains(line, "Identifier=") {
			builder.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(line)))
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

func printCapabilityReport(report *forensics.CapabilitiesReport) {
	if report == nil {
		return
	}

	threatEmoji := "🟢"
	threatLevel := "SAFE"

	switch report.ThreatScore {
	case forensics.Suspicious:
		threatEmoji = "🟡"
		threatLevel = "SUSPICIOUS"
	case forensics.Malicious:
		threatEmoji = "🔴"
		threatLevel = "MALICIOUS"
	}

	fmt.Printf("  Entropy: %.2f %s\n", report.Entropy, func() string {
		if report.IsPacked {
			return "(⚠️  PACKED/ENCRYPTED)"
		}
		return ""
	}())
	fmt.Printf("  Threat Level: %s %s\n", threatEmoji, threatLevel)

	if len(report.Capabilities) > 0 {
		fmt.Printf("\n  Detected Capabilities (%d):\n", len(report.Capabilities))
		for _, cap := range report.Capabilities {
			riskEmoji := "🟢"
			switch cap.RiskLevel {
			case forensics.Suspicious:
				riskEmoji = "🟡"
			case forensics.Malicious:
				riskEmoji = "🔴"
			}
			fmt.Printf("    %s %s - %s [%s]\n", riskEmoji, cap.Name, cap.Description, cap.Category)
		}
	}

	if verbose && len(report.Imports) > 0 {
		fmt.Printf("\n  Imported Libraries/Symbols (%d):\n", len(report.Imports))
		for i, imp := range report.Imports {
			if i >= 20 {
				fmt.Printf("    ... (%d more)\n", len(report.Imports)-20)
				break
			}
			fmt.Printf("    • %s\n", imp)
		}
	}
	fmt.Println()
}

func checkThreatIntelligence(sha256Hash string) {
	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
	defer cancel()

	found := false

	// FileHashes.io lookup
	if apiKey := os.Getenv("FILEHASHES_API_KEY"); apiKey != "" {
		client := threatintel.NewFileHashesClient(apiKey)
		record, err := client.LookupHash(ctx, sha256Hash)

		if err == nil && record != nil {
			found = true
			threatEmoji := "🟢"
			if record.ThreatLevel >= 7 {
				threatEmoji = "🔴"
			} else if record.ThreatLevel >= 4 {
				threatEmoji = "🟡"
			}

			fmt.Printf("  %s FileHashes.io: MATCH FOUND\n", threatEmoji)
			fmt.Printf("     Threat Level: %d/10\n", record.ThreatLevel)
			fmt.Printf("     Seen: %d times\n", record.SeenTimes)
			if !record.FirstSeen.IsZero() {
				fmt.Printf("     First Seen: %s\n", record.FirstSeen.Format("2006-01-02"))
			}
			if record.ThreatFamily != "" {
				fmt.Printf("     Threat Family: %s\n", record.ThreatFamily)
			}
			if len(record.DetectionNames) > 0 {
				fmt.Printf("     Detections: %s\n", strings.Join(record.DetectionNames, ", "))
			}
		}
	}

	if !found {
		fmt.Println("  ✅ No matches in global threat intelligence databases")
	}
	fmt.Println()
}

type IOCs struct {
	URLs       []string
	IPs        []string
	Domains    []string
	Emails     []string
	Paths      []string
	Suspicious []string
}

func extractStringsAndIOCs(path string) *IOCs {
	iocs := &IOCs{}

	cmd := exec.Command("strings", "-n", "8", path)
	output, err := cmd.Output()
	if err != nil {
		return iocs
	}

	lines := strings.Split(string(output), "\n")

	urlRegex := regexp.MustCompile(`https?://[a-zA-Z0-9\.\-]+(?:/[^\s]*)?`)
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9\-]+\.(com|net|org|io|xyz|onion|ru|cn)\b`)
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	pathRegex := regexp.MustCompile(`/(?:usr|etc|var|tmp|Library|System)/[^\s]+`)

	suspiciousKeywords := []string{"password", "token", "api_key", "secret", "backdoor", "shell", "exploit"}

	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) < 8 {
			continue
		}

		// URLs
		if matches := urlRegex.FindAllString(line, -1); len(matches) > 0 {
			for _, match := range matches {
				if !seen[match] {
					iocs.URLs = append(iocs.URLs, match)
					seen[match] = true
				}
			}
		}

		// IP addresses
		if matches := ipRegex.FindAllString(line, -1); len(matches) > 0 {
			for _, match := range matches {
				if !strings.HasPrefix(match, "127.") && !strings.HasPrefix(match, "0.0.0") && !seen[match] {
					iocs.IPs = append(iocs.IPs, match)
					seen[match] = true
				}
			}
		}

		// Domains
		if matches := domainRegex.FindAllString(line, -1); len(matches) > 0 {
			for _, match := range matches {
				if !seen[match] {
					iocs.Domains = append(iocs.Domains, match)
					seen[match] = true
				}
			}
		}

		// Emails
		if matches := emailRegex.FindAllString(line, -1); len(matches) > 0 {
			for _, match := range matches {
				if !seen[match] {
					iocs.Emails = append(iocs.Emails, match)
					seen[match] = true
				}
			}
		}

		// File paths
		if matches := pathRegex.FindAllString(line, -1); len(matches) > 0 {
			for _, match := range matches {
				if !seen[match] && len(iocs.Paths) < 10 {
					iocs.Paths = append(iocs.Paths, match)
					seen[match] = true
				}
			}
		}

		// Suspicious keywords
		lowerLine := strings.ToLower(line)
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(lowerLine, keyword) && !seen["susp:"+line] && len(iocs.Suspicious) < 10 {
				iocs.Suspicious = append(iocs.Suspicious, line)
				seen["susp:"+line] = true
			}
		}
	}

	return iocs
}

func printIOCs(iocs *IOCs) {
	if iocs == nil {
		fmt.Println("  No IOCs detected")
		fmt.Println()
		return
	}

	hasIOCs := false

	if len(iocs.URLs) > 0 {
		hasIOCs = true
		fmt.Printf("  🔗 URLs Found (%d):\n", len(iocs.URLs))
		for i, url := range iocs.URLs {
			if i >= 10 {
				fmt.Printf("     ... (%d more)\n", len(iocs.URLs)-10)
				break
			}
			fmt.Printf("     • %s\n", url)
		}
	}

	if len(iocs.IPs) > 0 {
		hasIOCs = true
		fmt.Printf("  🌐 IP Addresses (%d):\n", len(iocs.IPs))
		for i, ip := range iocs.IPs {
			if i >= 10 {
				fmt.Printf("     ... (%d more)\n", len(iocs.IPs)-10)
				break
			}
			fmt.Printf("     • %s\n", ip)
		}
	}

	if len(iocs.Domains) > 0 {
		hasIOCs = true
		fmt.Printf("  📡 Domains (%d):\n", len(iocs.Domains))
		for i, domain := range iocs.Domains {
			if i >= 10 {
				fmt.Printf("     ... (%d more)\n", len(iocs.Domains)-10)
				break
			}
			fmt.Printf("     • %s\n", domain)
		}
	}

	if len(iocs.Emails) > 0 {
		hasIOCs = true
		fmt.Printf("  📧 Email Addresses (%d):\n", len(iocs.Emails))
		for _, email := range iocs.Emails {
			fmt.Printf("     • %s\n", email)
		}
	}

	if len(iocs.Suspicious) > 0 {
		hasIOCs = true
		fmt.Printf("  ⚠️  Suspicious Strings (%d):\n", len(iocs.Suspicious))
		for _, susp := range iocs.Suspicious {
			fmt.Printf("     • %s\n", susp)
		}
	}

	if !hasIOCs {
		fmt.Println("  ✅ No suspicious indicators detected")
	}
	fmt.Println()
}

func printFlossStrings(res *forensics.FlossResult) {
	if res == nil {
		return
	}

	total := len(res.DecodedStrings) + len(res.StackStrings) + len(res.TightStrings)
	if total == 0 {
		fmt.Println("  ✅ No obfuscated or hidden strings detected")
		fmt.Println()
		return
	}

	fmt.Printf("  ⚠️  Obfuscated Strings Recovered (%d):\n", total)
	
	if len(res.DecodedStrings) > 0 {
		fmt.Printf("    🧬 Decoded Strings (%d):\n", len(res.DecodedStrings))
		for i, s := range res.DecodedStrings {
			if i >= 10 {
				fmt.Printf("      ... (%d more)\n", len(res.DecodedStrings)-10)
				break
			}
			fmt.Printf("      • %s\n", s)
		}
	}

	if len(res.StackStrings) > 0 {
		fmt.Printf("    📚 Stack Strings (%d):\n", len(res.StackStrings))
		for i, s := range res.StackStrings {
			if i >= 10 {
				fmt.Printf("      ... (%d more)\n", len(res.StackStrings)-10)
				break
			}
			fmt.Printf("      • %s\n", s)
		}
	}

	if len(res.TightStrings) > 0 {
		fmt.Printf("    🗜️ Tight Strings (%d):\n", len(res.TightStrings))
		for i, s := range res.TightStrings {
			if i >= 10 {
				fmt.Printf("      ... (%d more)\n", len(res.TightStrings)-10)
				break
			}
			fmt.Printf("      • %s\n", s)
		}
	}
	fmt.Println()
}

func runAIAnalysis(path string, hashes *Hashes, report *forensics.CapabilitiesReport, iocs *IOCs) {
	// Build comprehensive contextData for AI
	var contextData strings.Builder
	contextData.WriteString(fmt.Sprintf("Binary: %s\n", path))
	contextData.WriteString(fmt.Sprintf("SHA256: %s\n\n", hashes.SHA256))

	if report != nil {
		contextData.WriteString(fmt.Sprintf("Entropy: %.2f (Packed: %v)\n", report.Entropy, report.IsPacked))
		contextData.WriteString(fmt.Sprintf("Threat Score: %d\n", report.ThreatScore))

		if len(report.Capabilities) > 0 {
			contextData.WriteString("\nCapabilities:\n")
			for _, cap := range report.Capabilities {
				contextData.WriteString(fmt.Sprintf("- %s: %s\n", cap.Name, cap.Description))
			}
		}
	}

	if iocs != nil {
		if len(iocs.URLs) > 0 {
			contextData.WriteString(fmt.Sprintf("\nEmbedded URLs: %v\n", iocs.URLs))
		}
		if len(iocs.IPs) > 0 {
			contextData.WriteString(fmt.Sprintf("Embedded IPs: %v\n", iocs.IPs))
		}
		if len(iocs.Suspicious) > 0 {
			contextData.WriteString(fmt.Sprintf("Suspicious Strings: %v\n", iocs.Suspicious))
		}
	}

	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 45*time.Second)
	defer cancel()

	analysis, err := ai.AnalyzeBinarySemantics(ctx, contextData.String())
	if err != nil {
		fmt.Printf("  ⚠️  AI analysis failed: %v\n\n", err)
		return
	}

	fmt.Println("  " + strings.ReplaceAll(strings.TrimSpace(analysis), "\n", "\n  "))
	fmt.Println()
}

func runDarkScan(binaryPath string) *darkscan.IntegrationReport {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("  ⚠️  Failed to get home directory: %v\n\n", err)
		return nil
	}

	configPath := filepath.Join(home, ".aftersec", "config.yaml")
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("  ⚠️  Failed to load config: %v\n\n", err)
		return nil
	}

	if !cfg.Daemon.DarkScan.Enabled {
		fmt.Println("  ℹ️  DarkScan is disabled in config (enable in ~/.aftersec/config.yaml)")
		fmt.Println()
		return nil
	}

	var scanner interface {
		ScanWithReport(ctx stdcontext.Context, path string) (*darkscan.IntegrationReport, error)
		GetEngineCount() int
		Close() error
	}

	if cfg.Daemon.DarkScan.UseCLI {
		scanner, err = darkscan.NewCLIClient(&cfg.Daemon.DarkScan, cfg.Daemon.DarkScan.CLIBinaryPath)
	} else {
		scanner, err = darkscan.NewClient(&cfg.Daemon.DarkScan)
	}

	if err != nil {
		fmt.Printf("  ⚠️  Failed to initialize DarkScan: %v\n\n", err)
		return nil
	}
	defer scanner.Close()

	if scanner.GetEngineCount() == 0 {
		fmt.Println("  ℹ️  No DarkScan engines enabled (configure ClamAV, YARA, CAPA, or Viper)")
		fmt.Println()
		return nil
	}

	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 60*time.Second)
	defer cancel()

	report, err := scanner.ScanWithReport(ctx, binaryPath)
	if err != nil {
		fmt.Printf("  ⚠️  DarkScan failed: %v\n\n", err)
		return report
	}

	printDarkScanReport(report)
	return report
}

func printDarkScanReport(report *darkscan.IntegrationReport) {
	if report == nil {
		return
	}

	threatEmoji := "🟢"
	switch report.ThreatLevel {
	case darkscan.ThreatLevelLow:
		threatEmoji = "🟡"
	case darkscan.ThreatLevelMedium:
		threatEmoji = "🟠"
	case darkscan.ThreatLevelHigh, darkscan.ThreatLevelCritical:
		threatEmoji = "🔴"
	}

	fmt.Printf("  Engines: %s\n", strings.Join(report.Engines, ", "))
	fmt.Printf("  Scan Duration: %s\n", report.ScanDuration)
	fmt.Printf("  Threat Level: %s %s\n", threatEmoji, report.ThreatLevel)

	if report.Infected && len(report.Threats) > 0 {
		fmt.Printf("\n  ⚠️  MALWARE DETECTED - %d threat(s) found:\n", len(report.Threats))
		for _, threat := range report.Threats {
			fmt.Printf("    [%s] %s\n", threat.Engine, threat.Name)
			if threat.Description != "" {
				fmt.Printf("      └─ %s\n", threat.Description)
			}
		}
	} else {
		fmt.Println("  ✅ No threats detected by DarkScan engines")
	}
	fmt.Println()
}

func init() {
	analyzeBinaryCmd.Flags().BoolVar(&skipThreatIntel, "skip-threat-intel", false, "Skip threat intelligence lookups")
	analyzeBinaryCmd.Flags().BoolVar(&skipAI, "skip-ai", false, "Skip AI-powered analysis")
	analyzeBinaryCmd.Flags().BoolVar(&skipDarkScan, "skip-darkscan", false, "Skip DarkScan multi-engine malware scanning")
	analyzeBinaryCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show verbose output including all imports")

	rootCmd.AddCommand(analyzeBinaryCmd)
}
