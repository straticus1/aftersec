package forensics

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
)

// MemoryRegion represents a mapped memory region in a process
type MemoryRegion struct {
	StartAddress uint64
	EndAddress   uint64
	Size         uint64
	Permissions  string // r, w, x combinations
	Path         string // mapped file path if any
}

// MemoryFinding represents a suspicious pattern found in process memory
type MemoryFinding struct {
	PID            int
	ProcessName    string
	ProcessPath    string
	FindingType    string
	ThreatScore    float64
	MemoryRegion   string
	Indicators     map[string]interface{}
	Timestamp      time.Time
	Remediation    string
}

// MemoryForensicsEngine provides deep memory analysis capabilities
type MemoryForensicsEngine struct {
	mu                sync.RWMutex
	processWhitelist  map[string]bool
	suspiciousPatterns []*MemoryPattern
	db                storage.Manager
}

// MemoryPattern represents a signature to detect in memory
type MemoryPattern struct {
	Name        string
	Pattern     []byte
	Description string
	ThreatScore float64
	Category    string // shellcode, rop_gadget, credential, c2_config
}

var memoryEngine *MemoryForensicsEngine
var engineOnce sync.Once

// InitMemoryForensics initializes the memory forensics engine
func InitMemoryForensics(db storage.Manager) *MemoryForensicsEngine {
	engineOnce.Do(func() {
		memoryEngine = &MemoryForensicsEngine{
			processWhitelist: make(map[string]bool),
			suspiciousPatterns: []*MemoryPattern{
				// Common shellcode patterns
				{
					Name:        "x86_64_nop_sled",
					Pattern:     []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
					Description: "Potential NOP sled (shellcode indicator)",
					ThreatScore: 0.7,
					Category:    "shellcode",
				},
				{
					Name:        "mach_msg_trap",
					Pattern:     []byte{0x0F, 0x05}, // syscall instruction
					Description: "Syscall instruction in unusual location",
					ThreatScore: 0.6,
					Category:    "shellcode",
				},
				// ROP gadget patterns
				{
					Name:        "ret_instruction",
					Pattern:     []byte{0xC3}, // ret
					Description: "High density of RET instructions (ROP chain)",
					ThreatScore: 0.8,
					Category:    "rop_gadget",
				},
				// Credential harvesting indicators
				{
					Name:        "password_string",
					Pattern:     []byte("password:"),
					Description: "Plaintext credential in memory",
					ThreatScore: 0.9,
					Category:    "credential",
				},
				// Common C2 indicators
				{
					Name:        "http_beacon",
					Pattern:     []byte("User-Agent: Mozilla/5.0"),
					Description: "HTTP beacon configuration",
					ThreatScore: 0.5,
					Category:    "c2_config",
				},
			},
			db: db,
		}

		// Initialize process whitelist (trusted Apple processes)
		memoryEngine.processWhitelist["/usr/libexec/trustd"] = true
		memoryEngine.processWhitelist["/usr/sbin/securityd"] = true
		memoryEngine.processWhitelist["/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"] = true
	})
	return memoryEngine
}

// ScanProcessMemory performs comprehensive memory analysis on a process
func (mf *MemoryForensicsEngine) ScanProcessMemory(pid int) ([]MemoryFinding, error) {
	findings := []MemoryFinding{}

	// Get process information
	processName, processPath, err := getProcessInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("get process info: %w", err)
	}

	// Skip whitelisted processes
	mf.mu.RLock()
	if mf.processWhitelist[processPath] {
		mf.mu.RUnlock()
		return findings, nil
	}
	mf.mu.RUnlock()

	// Get memory regions
	regions, err := getMemoryRegions(pid)
	if err != nil {
		return nil, fmt.Errorf("get memory regions: %w", err)
	}

	// Analyze each memory region
	for _, region := range regions {
		// 1. Check for RWX pages (write + execute is suspicious)
		if strings.Contains(region.Permissions, "w") && strings.Contains(region.Permissions, "x") {
			findings = append(findings, MemoryFinding{
				PID:          pid,
				ProcessName:  processName,
				ProcessPath:  processPath,
				FindingType:  "rwx_page",
				ThreatScore:  0.8,
				MemoryRegion: fmt.Sprintf("%x-%x", region.StartAddress, region.EndAddress),
				Indicators: map[string]interface{}{
					"permissions": region.Permissions,
					"size":        region.Size,
					"path":        region.Path,
				},
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Investigate process %d for code injection. RWX pages are unusual.", pid),
			})
		}

		// 2. Check executable regions for shellcode patterns
		if strings.Contains(region.Permissions, "x") {
			// Read memory content (simplified - would use vm_read in production)
			content, err := readMemoryRegion(pid, region)
			if err != nil {
				continue
			}

			// Scan for suspicious patterns
			patternFindings := mf.scanForPatterns(content, region)
			for _, pf := range patternFindings {
				findings = append(findings, MemoryFinding{
					PID:          pid,
					ProcessName:  processName,
					ProcessPath:  processPath,
					FindingType:  pf.Category,
					ThreatScore:  pf.ThreatScore,
					MemoryRegion: fmt.Sprintf("%x-%x", region.StartAddress, region.EndAddress),
					Indicators: map[string]interface{}{
						"pattern":     pf.Name,
						"description": pf.Description,
					},
					Timestamp:   time.Now(),
					Remediation: fmt.Sprintf("Pattern '%s' detected. Investigate for malicious code.", pf.Name),
				})
			}
		}

		// 3. Extract strings and scan for IOCs
		if len(findings) < 100 { // Limit findings per process
			stringFindings := mf.extractAndAnalyzeStrings(pid, processName, processPath, region)
			findings = append(findings, stringFindings...)
		}
	}

	// 4. Detect thread injection
	threadFindings, err := mf.detectThreadInjection(pid, processName, processPath)
	if err == nil {
		findings = append(findings, threadFindings...)
	}

	// 5. Detect process hollowing
	hollowingFinding, err := mf.detectProcessHollowing(pid, processName, processPath)
	if err == nil && hollowingFinding != nil {
		findings = append(findings, *hollowingFinding)
	}

	// Log to database
	if mf.db != nil {
		for _, finding := range findings {
			mf.db.LogTelemetryEvent(
				"memory_forensics",
				finding.FindingType,
				severityFromScore(finding.ThreatScore),
				fmt.Sprintf(`{"pid": %d, "process": "%s", "region": "%s"}`,
					finding.PID, finding.ProcessName, finding.MemoryRegion),
			)
		}
	}

	return findings, nil
}

// scanForPatterns searches memory content for suspicious patterns
func (mf *MemoryForensicsEngine) scanForPatterns(content []byte, region MemoryRegion) []*MemoryPattern {
	matches := []*MemoryPattern{}

	mf.mu.RLock()
	defer mf.mu.RUnlock()

	for _, pattern := range mf.suspiciousPatterns {
		// Simple pattern matching (in production, use Boyer-Moore or similar)
		if bytes.Contains(content, pattern.Pattern) {
			matches = append(matches, pattern)
		}

		// Special case: detect high density of RET instructions (ROP chains)
		if pattern.Name == "ret_instruction" {
			retCount := bytes.Count(content, pattern.Pattern)
			if retCount > 50 && len(content) < 4096 {
				matches = append(matches, pattern)
			}
		}
	}

	return matches
}

// extractAndAnalyzeStrings extracts printable strings and analyzes them for IOCs
func (mf *MemoryForensicsEngine) extractAndAnalyzeStrings(pid int, processName, processPath string, region MemoryRegion) []MemoryFinding {
	findings := []MemoryFinding{}

	content, err := readMemoryRegion(pid, region)
	if err != nil {
		return findings
	}

	// Extract printable strings (ASCII 32-126)
	strings := extractStrings(content, 8) // Minimum string length of 8

	// Regex patterns for IOCs
	urlPattern := regexp.MustCompile(`https?://[a-zA-Z0-9\.\-]+(?:/[^\s]*)?`)
	ipPattern := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	keyPattern := regexp.MustCompile(`(?i)(api[_\-]?key|secret|token|password)\s*[:=]\s*[a-zA-Z0-9\-_\.]+`)

	for _, str := range strings {
		// Check for URLs (potential C2 or exfiltration endpoints)
		if urlPattern.MatchString(str) {
			findings = append(findings, MemoryFinding{
				PID:          pid,
				ProcessName:  processName,
				ProcessPath:  processPath,
				FindingType:  "url_in_memory",
				ThreatScore:  0.5,
				MemoryRegion: fmt.Sprintf("%x-%x", region.StartAddress, region.EndAddress),
				Indicators: map[string]interface{}{
					"url": str,
				},
				Timestamp:   time.Now(),
				Remediation: "Verify if URL is legitimate. May indicate C2 communication.",
			})
		}

		// Check for IP addresses
		if ipPattern.MatchString(str) && !strings.Contains(str, "127.0.0.1") && !strings.Contains(str, "0.0.0.0") {
			findings = append(findings, MemoryFinding{
				PID:          pid,
				ProcessName:  processName,
				ProcessPath:  processPath,
				FindingType:  "ip_address_in_memory",
				ThreatScore:  0.4,
				MemoryRegion: fmt.Sprintf("%x-%x", region.StartAddress, region.EndAddress),
				Indicators: map[string]interface{}{
					"ip": str,
				},
				Timestamp:   time.Now(),
				Remediation: "Check if IP is associated with known threat actors.",
			})
		}

		// Check for credentials
		if keyPattern.MatchString(str) {
			findings = append(findings, MemoryFinding{
				PID:          pid,
				ProcessName:  processName,
				ProcessPath:  processPath,
				FindingType:  "credential_in_memory",
				ThreatScore:  0.9,
				MemoryRegion: fmt.Sprintf("%x-%x", region.StartAddress, region.EndAddress),
				Indicators: map[string]interface{}{
					"redacted": "[REDACTED]",
				},
				Timestamp:   time.Now(),
				Remediation: "Sensitive credentials detected in process memory. Possible credential theft.",
			})
		}
	}

	return findings
}

// detectThreadInjection checks for suspicious thread creation patterns
func (mf *MemoryForensicsEngine) detectThreadInjection(pid int, processName, processPath string) ([]MemoryFinding, error) {
	findings := []MemoryFinding{}

	// On macOS, we can use task_threads() via mach APIs
	// For this implementation, we use a heuristic approach

	// Check for threads with unusual start addresses (outside normal code sections)
	// This is a simplified version - production would use mach_port_t and thread_get_state()

	threadInfo, err := getThreadInfo(pid)
	if err != nil {
		return findings, err
	}

	// Heuristic: If process has > 20 threads and wasn't spawned from a known source, flag it
	if threadInfo.ThreadCount > 20 {
		findings = append(findings, MemoryFinding{
			PID:         pid,
			ProcessName: processName,
			ProcessPath: processPath,
			FindingType: "excessive_threads",
			ThreatScore: 0.6,
			Indicators: map[string]interface{}{
				"thread_count": threadInfo.ThreadCount,
			},
			Timestamp:   time.Now(),
			Remediation: "Process has unusual number of threads. May indicate thread injection.",
		})
	}

	return findings, nil
}

// detectProcessHollowing detects if a process has been hollowed (code replaced)
func (mf *MemoryForensicsEngine) detectProcessHollowing(pid int, processName, processPath string) (*MemoryFinding, error) {
	// Process hollowing detection:
	// 1. Read the executable file from disk
	// 2. Compare the TEXT segment in memory vs. on disk
	// 3. Significant differences indicate hollowing

	regions, err := getMemoryRegions(pid)
	if err != nil {
		return nil, err
	}

	// Find the __TEXT segment
	var textRegion *MemoryRegion
	for i := range regions {
		if strings.Contains(regions[i].Path, processPath) && strings.Contains(regions[i].Permissions, "x") {
			textRegion = &regions[i]
			break
		}
	}

	if textRegion == nil {
		return nil, nil
	}

	// Read memory content
	memoryContent, err := readMemoryRegion(pid, *textRegion)
	if err != nil {
		return nil, err
	}

	// Read disk content (simplified - would need proper Mach-O parsing)
	diskContent, err := readDiskSection(processPath, "__TEXT")
	if err != nil {
		return nil, err
	}

	// Compare hashes or byte-by-byte
	if !bytes.Equal(memoryContent[:min(len(memoryContent), len(diskContent))], diskContent[:min(len(memoryContent), len(diskContent))]) {
		return &MemoryFinding{
			PID:         pid,
			ProcessName: processName,
			ProcessPath: processPath,
			FindingType: "process_hollowing",
			ThreatScore: 0.95,
			Indicators: map[string]interface{}{
				"disk_hash":   hashBytes(diskContent),
				"memory_hash": hashBytes(memoryContent),
			},
			Timestamp:   time.Now(),
			Remediation: "Process __TEXT segment differs from disk. Likely process hollowing attack. Terminate immediately.",
		}, nil
	}

	return nil, nil
}

// Helper functions

func getProcessInfo(pid int) (name, path string, err error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=,command=").Output()
	if err != nil {
		return "", "", err
	}
	parts := strings.Fields(string(out))
	if len(parts) > 0 {
		name = parts[0]
	}
	if len(parts) > 1 {
		path = parts[1]
	}
	return
}

func getMemoryRegions(pid int) ([]MemoryRegion, error) {
	// On macOS, use vmmap to enumerate memory regions
	out, err := exec.Command("vmmap", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, err
	}

	regions := []MemoryRegion{}
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		if !strings.Contains(line, "-") {
			continue
		}

		// Parse vmmap output format
		// Example: "Stack  000000016f3e0000-000000016f800000 [ 4352K] rw-/rwx SM=COW"
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Extract address range
		addrParts := strings.Split(fields[1], "-")
		if len(addrParts) != 2 {
			continue
		}

		start, _ := strconv.ParseUint(addrParts[0], 16, 64)
		end, _ := strconv.ParseUint(addrParts[1], 16, 64)

		var perms string
		if len(fields) > 3 {
			perms = fields[3]
		}

		regions = append(regions, MemoryRegion{
			StartAddress: start,
			EndAddress:   end,
			Size:         end - start,
			Permissions:  perms,
			Path:         fields[0],
		})
	}

	return regions, nil
}

func readMemoryRegion(pid int, region MemoryRegion) ([]byte, error) {
	// In production, use mach_vm_read() via CGO
	// For this implementation, we'll simulate by reading a limited sample
	// This is a placeholder - real implementation would use:
	// mach_port_t task;
	// task_for_pid(mach_task_self(), pid, &task);
	// vm_read(task, address, size, &data, &dataSize);

	// Return dummy data for now
	return make([]byte, min(4096, int(region.Size))), nil
}

func readDiskSection(path, section string) ([]byte, error) {
	// Use otool or direct Mach-O parsing to read section from disk
	// Placeholder implementation
	return make([]byte, 4096), nil
}

func extractStrings(data []byte, minLen int) []string {
	strings := []string{}
	current := []byte{}

	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				strings = append(strings, string(current))
			}
			current = []byte{}
		}
	}

	if len(current) >= minLen {
		strings = append(strings, string(current))
	}

	return strings
}

type ThreadInfo struct {
	ThreadCount int
}

func getThreadInfo(pid int) (*ThreadInfo, error) {
	// In production, use task_threads() mach API
	// Simplified: parse ps output
	out, err := exec.Command("ps", "-M", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return &ThreadInfo{ThreadCount: 1}, nil
	}

	lines := strings.Split(string(out), "\n")
	return &ThreadInfo{ThreadCount: len(lines) - 1}, nil
}

func hashBytes(data []byte) string {
	// Simple hash for comparison (use crypto/sha256 in production)
	return hex.EncodeToString(data[:min(32, len(data))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func severityFromScore(score float64) string {
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.6 {
		return "high"
	} else if score >= 0.4 {
		return "medium"
	}
	return "low"
}
