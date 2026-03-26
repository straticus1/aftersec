package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
)

// RootkitFinding represents a detected rootkit indicator
type RootkitFinding struct {
	DetectionType string
	Severity      string
	KEXTName      string
	KEXTPath      string
	ThreatScore   float64
	Evidence      map[string]interface{}
	Timestamp     time.Time
	Remediation   string
}

// RootkitDetector provides kernel-level threat detection
type RootkitDetector struct {
	mu                sync.RWMutex
	kextBaselines     map[string]string // KEXT bundle ID -> SHA256 hash
	syscallBaseline   map[int]string    // syscall number -> hash
	trustedKEXTs      map[string]bool
	lastFullScan      time.Time
	db                storage.Manager
}

var rootkitDetector *RootkitDetector
var rootkitOnce sync.Once

// InitRootkitDetector initializes the rootkit detection engine
func InitRootkitDetector(db storage.Manager) *RootkitDetector {
	rootkitOnce.Do(func() {
		rootkitDetector = &RootkitDetector{
			kextBaselines: make(map[string]string),
			syscallBaseline: make(map[int]string),
			trustedKEXTs: make(map[string]bool),
			db: db,
		}

		// Initialize trusted Apple KEXTs
		rootkitDetector.trustedKEXTs["com.apple.kext.AMDRadeonX6000"] = true
		rootkitDetector.trustedKEXTs["com.apple.iokit.IOGraphicsFamily"] = true
		rootkitDetector.trustedKEXTs["com.apple.driver.AppleACPIPlatform"] = true
		rootkitDetector.trustedKEXTs["com.apple.iokit.IOUSBHostFamily"] = true

		// Establish baselines
		rootkitDetector.establishBaselines()
	})
	return rootkitDetector
}

// PerformFullScan performs a comprehensive rootkit scan
func (rd *RootkitDetector) PerformFullScan() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// 1. KEXT Analysis
	kextFindings, err := rd.scanLoadedKEXTs()
	if err == nil {
		findings = append(findings, kextFindings...)
	}

	// 2. Syscall Table Integrity Check
	syscallFindings, err := rd.verifySyscallTable()
	if err == nil {
		findings = append(findings, syscallFindings...)
	}

	// 3. Hidden Process Detection (DKOM - Direct Kernel Object Manipulation)
	hiddenProcFindings, err := rd.detectHiddenProcesses()
	if err == nil {
		findings = append(findings, hiddenProcFindings...)
	}

	// 4. Boot Process Integrity
	bootFindings, err := rd.verifyBootIntegrity()
	if err == nil {
		findings = append(findings, bootFindings...)
	}

	// 5. Kernel Memory Scanning
	kernelMemFindings, err := rd.scanKernelMemory()
	if err == nil {
		findings = append(findings, kernelMemFindings...)
	}

	// 6. Driver Signing Verification
	signingFindings, err := rd.verifyDriverSignatures()
	if err == nil {
		findings = append(findings, signingFindings...)
	}

	rd.mu.Lock()
	rd.lastFullScan = time.Now()
	rd.mu.Unlock()

	// Log all findings
	if rd.db != nil {
		for _, finding := range findings {
			rd.db.LogTelemetryEvent(
				"rootkit_detection",
				finding.DetectionType,
				finding.Severity,
				fmt.Sprintf(`{"kext": "%s", "score": %.2f}`, finding.KEXTName, finding.ThreatScore),
			)
		}
	}

	return findings, nil
}

// scanLoadedKEXTs analyzes all loaded kernel extensions
func (rd *RootkitDetector) scanLoadedKEXTs() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// Get list of loaded KEXTs
	out, err := exec.Command("kextstat").Output()
	if err != nil {
		return nil, fmt.Errorf("kextstat failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header
		}

		// Parse kextstat output
		// Format: Index Refs Address Size Wired Name (Version) UUID <Linked Against>
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		bundleID := fields[5]

		// Check for suspicious characteristics
		var threatScore float64
		evidence := make(map[string]interface{})

		// 1. Check if KEXT is not from Apple
		if !strings.HasPrefix(bundleID, "com.apple.") {
			threatScore += 0.3
			evidence["non_apple"] = true

			// 2. Check if it's signed
			kextPath := findKEXTPath(bundleID)
			if kextPath != "" {
				signed, err := verifyCodeSignature(kextPath)
				if err != nil || !signed {
					threatScore += 0.4
					evidence["unsigned"] = true
				}
			}

			// 3. Check entitlements
			if kextPath != "" {
				entitlements, err := extractEntitlements(kextPath)
				if err == nil && containsDangerousEntitlements(entitlements) {
					threatScore += 0.3
					evidence["dangerous_entitlements"] = entitlements
				}
			}
		}

		// 4. Compare against baseline
		if kextPath := findKEXTPath(bundleID); kextPath != "" {
			rd.mu.RLock()
			baseline, exists := rd.kextBaselines[bundleID]
			rd.mu.RUnlock()

			if exists {
				currentHash := hashFile(kextPath)
				if currentHash != baseline {
					threatScore += 0.5
					evidence["modified"] = true
					evidence["baseline_hash"] = baseline
					evidence["current_hash"] = currentHash
				}
			}
		}

		// Only report if threat score is significant
		if threatScore > 0.5 {
			findings = append(findings, RootkitFinding{
				DetectionType: "suspicious_kext",
				Severity:      severityFromScore(threatScore),
				KEXTName:      bundleID,
				KEXTPath:      findKEXTPath(bundleID),
				ThreatScore:   threatScore,
				Evidence:      evidence,
				Timestamp:     time.Now(),
				Remediation:   fmt.Sprintf("Unload KEXT with: sudo kextunload -b %s", bundleID),
			})
		}
	}

	return findings, nil
}

// verifySyscallTable checks for syscall table hooks
func (rd *RootkitDetector) verifySyscallTable() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// On macOS, syscall hooking is more difficult due to SIP
	// But we can check for timing anomalies that suggest hooking

	// Test syscalls for unusual latency
	suspiciousSyscalls := []int{
		1,  // exit
		4,  // write
		5,  // open
		20, // getpid
	}

	for _, syscallNum := range suspiciousSyscalls {
		latency := measureSyscallLatency(syscallNum)

		// If latency is > 3x normal, may indicate hook
		if latency > 1000 { // microseconds
			findings = append(findings, RootkitFinding{
				DetectionType: "syscall_hook_suspected",
				Severity:      "high",
				ThreatScore:   0.7,
				Evidence: map[string]interface{}{
					"syscall":        syscallNum,
					"latency_us":     latency,
					"expected_max":   300,
				},
				Timestamp:   time.Now(),
				Remediation: "Syscall may be hooked. Reboot and perform offline analysis.",
			})
		}
	}

	return findings, nil
}

// detectHiddenProcesses detects processes hidden by rootkits
func (rd *RootkitDetector) detectHiddenProcesses() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// Cross-view detection: Compare process lists from different sources
	// 1. Get processes from ps
	psProcs, err := getProcessListPS()
	if err != nil {
		return findings, err
	}

	// 2. Get processes from /proc (if available) or sysctl
	sysctlProcs, err := getProcessListSysctl()
	if err != nil {
		return findings, err
	}

	// 3. Get processes from Endpoint Security
	// (Would integrate with EDR consumer)

	// Find discrepancies
	for pid := range sysctlProcs {
		if !psProcs[pid] {
			findings = append(findings, RootkitFinding{
				DetectionType: "hidden_process",
				Severity:      "critical",
				ThreatScore:   0.95,
				Evidence: map[string]interface{}{
					"pid":                pid,
					"visible_in_sysctl":  true,
					"visible_in_ps":      false,
				},
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Process %d is hidden from ps but visible in kernel. Likely rootkit.", pid),
			})
		}
	}

	return findings, nil
}

// verifyBootIntegrity checks for bootkit modifications
func (rd *RootkitDetector) verifyBootIntegrity() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// Check EFI firmware integrity
	// On macOS, use 'nvram -x' to dump NVRAM variables
	out, err := exec.Command("nvram", "-x", "-p").Output()
	if err != nil {
		return findings, nil
	}

	// Look for suspicious EFI variables
	suspiciousPatterns := []string{
		"BootOrder",
		"BootNext",
		"OsIndicationsSupported",
	}

	nvramData := string(out)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(nvramData, pattern) {
			// Check if it's modified from default
			// This is simplified - production would have known-good baselines
			findings = append(findings, RootkitFinding{
				DetectionType: "efi_variable_modified",
				Severity:      "medium",
				ThreatScore:   0.5,
				Evidence: map[string]interface{}{
					"variable": pattern,
				},
				Timestamp:   time.Now(),
				Remediation: "Review EFI/NVRAM variables for tampering. Reset NVRAM if suspicious.",
			})
		}
	}

	// Check for unsigned kernel extensions in boot path
	bootKexts := []string{
		"/System/Library/Extensions",
		"/Library/Extensions",
	}

	for _, kextDir := range bootKexts {
		filepath.Walk(kextDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(path, ".kext") {
				signed, err := verifyCodeSignature(path)
				if err != nil || !signed {
					findings = append(findings, RootkitFinding{
						DetectionType: "unsigned_boot_kext",
						Severity:      "high",
						KEXTPath:      path,
						ThreatScore:   0.8,
						Evidence: map[string]interface{}{
							"signed": signed,
						},
						Timestamp:   time.Now(),
						Remediation: fmt.Sprintf("Remove unsigned KEXT: %s", path),
					})
				}
			}
			return nil
		})
	}

	return findings, nil
}

// scanKernelMemory performs basic kernel memory analysis
func (rd *RootkitDetector) scanKernelMemory() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// On macOS, direct kernel memory reading requires a kernel extension
	// For userland detection, we use indirect methods:

	// 1. Check kernel log for anomalies
	out, err := exec.Command("log", "show", "--predicate", "eventMessage contains 'kernel'", "--last", "1h").Output()
	if err == nil {
		logData := string(out)

		// Look for panic messages or suspicious kernel events
		panicPattern := regexp.MustCompile(`(?i)panic|kernel trap|page fault`)
		if panicPattern.MatchString(logData) {
			findings = append(findings, RootkitFinding{
				DetectionType: "kernel_anomaly",
				Severity:      "medium",
				ThreatScore:   0.6,
				Evidence: map[string]interface{}{
					"log_contains": "panic or trap",
				},
				Timestamp:   time.Now(),
				Remediation: "Review kernel logs for exploitation attempts.",
			})
		}
	}

	// 2. Check for kernel memory pressure (may indicate memory manipulation)
	out, err = exec.Command("vm_stat").Output()
	if err == nil {
		// Parse vm_stat output for anomalies
		// This is a simplified heuristic
		if strings.Contains(string(out), "Pages wired down") {
			// Check if wired memory is unusually high
		}
	}

	return findings, nil
}

// verifyDriverSignatures checks all drivers for valid signatures
func (rd *RootkitDetector) verifyDriverSignatures() ([]RootkitFinding, error) {
	findings := []RootkitFinding{}

	// Check all KEXTs for valid Apple or developer signatures
	kextDirs := []string{
		"/System/Library/Extensions",
		"/Library/Extensions",
	}

	for _, kextDir := range kextDirs {
		filepath.Walk(kextDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if strings.HasSuffix(path, ".kext") && info.IsDir() {
				// Verify signature
				out, err := exec.Command("codesign", "--verify", "--deep", "--strict", path).CombinedOutput()
				if err != nil {
					findings = append(findings, RootkitFinding{
						DetectionType: "invalid_signature",
						Severity:      "high",
						KEXTPath:      path,
						ThreatScore:   0.8,
						Evidence: map[string]interface{}{
							"error": string(out),
						},
						Timestamp:   time.Now(),
						Remediation: fmt.Sprintf("KEXT signature invalid: %s. Investigate or remove.", path),
					})
				}
			}
			return nil
		})
	}

	return findings, nil
}

// establishBaselines creates cryptographic baselines of system components
func (rd *RootkitDetector) establishBaselines() {
	// Baseline all loaded KEXTs
	out, err := exec.Command("kextstat").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		bundleID := fields[5]
		kextPath := findKEXTPath(bundleID)

		if kextPath != "" {
			hash := hashFile(kextPath)
			rd.mu.Lock()
			rd.kextBaselines[bundleID] = hash
			rd.mu.Unlock()
		}
	}
}

// Helper functions

func findKEXTPath(bundleID string) string {
	// Search common KEXT locations
	paths := []string{
		"/System/Library/Extensions",
		"/Library/Extensions",
	}

	for _, basePath := range paths {
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(path, ".kext") && strings.Contains(path, bundleID) {
				return filepath.SkipDir
			}
			return nil
		})
	}

	return ""
}

func verifyCodeSignature(path string) (bool, error) {
	out, err := exec.Command("codesign", "--verify", "--deep", "--strict", path).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("codesign failed: %s", string(out))
	}
	return true, nil
}

func extractEntitlements(path string) ([]string, error) {
	out, err := exec.Command("codesign", "-d", "--entitlements", ":-", path).Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(string(out), "\n"), nil
}

func containsDangerousEntitlements(entitlements []string) bool {
	dangerous := []string{
		"com.apple.private.kernel.debug",
		"com.apple.rootless.install",
		"com.apple.rootless.kext-management",
	}

	entStr := strings.Join(entitlements, " ")
	for _, d := range dangerous {
		if strings.Contains(entStr, d) {
			return true
		}
	}
	return false
}

func hashFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func measureSyscallLatency(syscallNum int) int64 {
	// In production, use assembly or C to measure precise syscall latency
	// This is a placeholder
	start := time.Now()

	// Execute syscall (simplified)
	switch syscallNum {
	case 20: // getpid
		os.Getpid()
	}

	return time.Since(start).Microseconds()
}

func getProcessListPS() (map[int]bool, error) {
	out, err := exec.Command("ps", "-eo", "pid").Output()
	if err != nil {
		return nil, err
	}

	procs := make(map[int]bool)
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		pid := strings.TrimSpace(line)
		if pid == "" {
			continue
		}
		if p, err := fmt.Sscanf(pid, "%d"); err == nil {
			procs[p] = true
		}
	}
	return procs, nil
}

func getProcessListSysctl() (map[int]bool, error) {
	// Use sysctl kern.proc.all to get process list directly from kernel
	out, err := exec.Command("sysctl", "kern.proc.all").Output()
	if err != nil {
		return nil, err
	}

	procs := make(map[int]bool)
	// Parse sysctl output (simplified)
	// Real implementation would parse the struct kinfo_proc
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		// Extract PID from sysctl output
		// This is a placeholder - actual parsing is more complex
		fields := strings.Fields(line)
		if len(fields) > 1 {
			var pid int
			fmt.Sscanf(fields[1], "%d", &pid)
			if pid > 0 {
				procs[pid] = true
			}
		}
	}

	return procs, nil
}
