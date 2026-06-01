//go:build linux

package forensics

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
)

// RootkitFinding represents a detected rootkit indicator.
type RootkitFinding struct {
	DetectionType string
	Severity      string
	KEXTName      string // reused on Linux for kernel module name
	KEXTPath      string
	ThreatScore   float64
	Evidence      map[string]interface{}
	Timestamp     time.Time
	Remediation   string
}

// RootkitDetector provides kernel-level threat detection on Linux.
type RootkitDetector struct {
	mu sync.RWMutex
	db storage.Manager
}

var rootkitDetector *RootkitDetector
var rootkitOnce sync.Once

// InitRootkitDetector returns the singleton detector, creating it on first call.
func InitRootkitDetector(db storage.Manager) *RootkitDetector {
	rootkitOnce.Do(func() {
		rootkitDetector = &RootkitDetector{db: db}
	})
	return rootkitDetector
}

// PerformFullScan runs four independent detection passes and returns all findings.
func (rd *RootkitDetector) PerformFullScan() ([]RootkitFinding, error) {
	var findings []RootkitFinding

	if f, err := rd.detectHiddenProcesses(); err == nil {
		findings = append(findings, f...)
	}
	if f, err := rd.detectLDPreload(); err == nil {
		findings = append(findings, f...)
	}
	if f, err := rd.auditKernelModules(); err == nil {
		findings = append(findings, f...)
	}
	if f, err := rd.detectOrphanedConnections(); err == nil {
		findings = append(findings, f...)
	}

	if rd.db != nil {
		for _, f := range findings {
			rd.db.LogTelemetryEvent("rootkit_detection", f.DetectionType, f.Severity,
				fmt.Sprintf(`{"module": "%s", "score": %.2f}`, f.KEXTName, f.ThreatScore))
		}
	}
	return findings, nil
}

// ── hidden process detection ──────────────────────────────────────────────────
//
// Technique: compare /proc readdir (vulnerable to getdents hook) vs direct
// stat("/proc/<pid>/stat") calls (bypasses directory-listing hook). PIDs that
// are stat-accessible but missing from the readdir listing indicate a rootkit
// hiding entries via a hooked getdents/getdents64 syscall.

func (rd *RootkitDetector) detectHiddenProcesses() ([]RootkitFinding, error) {
	// Method A: readdir /proc → visible PIDs
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	visible := make(map[int]bool, len(entries))
	maxPID := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil && pid > 0 {
			visible[pid] = true
			if pid > maxPID {
				maxPID = pid
			}
		}
	}

	// Cap probe range: read kernel pid_max, hard-cap at 32768 for scan time.
	probeMax := 32768
	if data, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		var v int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v); err == nil && v < probeMax {
			probeMax = v
		}
	}
	if maxPID+100 < probeMax {
		probeMax = maxPID + 100 // no need to scan beyond seen max + small buffer
	}

	// Method B: direct stat access (one syscall per PID, fast)
	var findings []RootkitFinding
	for pid := 1; pid <= probeMax; pid++ {
		if visible[pid] {
			continue
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
			continue // process does not exist
		}
		// Stat succeeded but readdir didn't show it — getdents hook detected.
		comm := procReadComm(pid)
		findings = append(findings, RootkitFinding{
			DetectionType: "hidden_process",
			Severity:      "critical",
			ThreatScore:   0.95,
			Evidence: map[string]interface{}{
				"pid":             pid,
				"comm":            comm,
				"in_proc_readdir": false,
				"stat_accessible": true,
			},
			Timestamp:   time.Now(),
			Remediation: fmt.Sprintf("PID %d (%s) hidden from /proc readdir but accessible via direct path — likely getdents hook rootkit.", pid, comm),
		})
	}
	return findings, nil
}

// ── LD_PRELOAD injection ──────────────────────────────────────────────────────

func (rd *RootkitDetector) detectLDPreload() ([]RootkitFinding, error) {
	var findings []RootkitFinding

	// System-wide injection via /etc/ld.so.preload
	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' {
				continue
			}
			score := 0.65
			if strings.HasPrefix(line, "/tmp") || strings.HasPrefix(line, "/dev/shm") ||
				strings.HasPrefix(line, "/var/tmp") {
				score = 0.95
			}
			findings = append(findings, RootkitFinding{
				DetectionType: "ldpreload_injection",
				Severity:      severityFromScoreRK(score),
				ThreatScore:   score,
				Evidence: map[string]interface{}{
					"source":  "/etc/ld.so.preload",
					"library": line,
				},
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Remove suspicious entry from /etc/ld.so.preload: %s", line),
			})
		}
	}

	// Per-process LD_PRELOAD in /proc/<pid>/environ (null-delimited)
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid <= 0 {
			continue
		}
		environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			continue
		}
		for _, env := range strings.Split(string(environ), "\x00") {
			if !strings.HasPrefix(env, "LD_PRELOAD=") {
				continue
			}
			libs := strings.TrimPrefix(env, "LD_PRELOAD=")
			score := 0.70
			if strings.Contains(libs, "/tmp") || strings.Contains(libs, "/dev/shm") {
				score = 0.95
			}
			comm := procReadComm(pid)
			findings = append(findings, RootkitFinding{
				DetectionType: "ldpreload_injection",
				Severity:      severityFromScoreRK(score),
				ThreatScore:   score,
				Evidence: map[string]interface{}{
					"pid":       pid,
					"comm":      comm,
					"libraries": libs,
				},
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Process %d (%s) has LD_PRELOAD=%s — investigate for userland rootkit.", pid, comm, libs),
			})
		}
	}
	return findings, nil
}

// ── kernel module audit ───────────────────────────────────────────────────────

// knownRootkitModules is a small list of documented Linux rootkit module names.
var knownRootkitModules = []string{
	"diamorphine", "reptile", "azazel", "necurs", "r0kit", "suterusu",
	"adore", "knark", "rkit", "enyelkm", "kbeast",
}

func (rd *RootkitDetector) auditKernelModules() ([]RootkitFinding, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}

	// Build /sys/module set for cross-view comparison.
	sysModules := make(map[string]bool)
	if entries, err := os.ReadDir("/sys/module"); err == nil {
		for _, e := range entries {
			sysModules[e.Name()] = true
		}
	}

	var findings []RootkitFinding
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := fields[0]

		var score float64
		var reasons []string

		// Known rootkit name
		lower := strings.ToLower(name)
		for _, rk := range knownRootkitModules {
			if strings.Contains(lower, rk) {
				score += 0.6
				reasons = append(reasons, fmt.Sprintf("name matches known rootkit: %s", rk))
				break
			}
		}

		// Generic suspicious keywords
		for _, kw := range []string{"hide", "hook", "stealth", "backdoor", "keylog", "sniff"} {
			if strings.Contains(lower, kw) {
				score += 0.4
				reasons = append(reasons, fmt.Sprintf("name contains suspicious keyword: %s", kw))
				break
			}
		}

		// Kernel taint flags via /sys/module/<name>/taint
		if taintData, err := os.ReadFile(fmt.Sprintf("/sys/module/%s/taint", name)); err == nil {
			taint := strings.TrimSpace(string(taintData))
			if taint != "" {
				score += 0.25
				reasons = append(reasons, fmt.Sprintf("kernel taint flags: %s", taint))
			}
		}

		// DKOM indicator: visible in /proc/modules but absent from /sys/module
		if !sysModules[name] {
			score += 0.45
			reasons = append(reasons, "module in /proc/modules but absent from /sys/module (possible DKOM)")
		}

		if score < 0.4 {
			continue
		}
		score = min(score, 1.0)
		findings = append(findings, RootkitFinding{
			DetectionType: "suspicious_kernel_module",
			Severity:      severityFromScoreRK(score),
			KEXTName:      name,
			ThreatScore:   score,
			Evidence: map[string]interface{}{
				"module":  name,
				"reasons": reasons,
			},
			Timestamp:   time.Now(),
			Remediation: fmt.Sprintf("Investigate module '%s': sudo rmmod %s && dmesg | tail -20", name, name),
		})
	}
	return findings, nil
}

// ── orphaned TCP connection detection ────────────────────────────────────────
//
// Technique: collect all socket inodes referenced by process file descriptors,
// then compare against inodes in /proc/net/tcp[6]. An ESTABLISHED or LISTEN
// socket with no owning process fd indicates a hidden process or kernel backdoor.

type tcpConnInfo struct {
	local  string
	remote string
	state  string // raw hex state from /proc/net/tcp
}

func (rd *RootkitDetector) detectOrphanedConnections() ([]RootkitFinding, error) {
	conns := make(map[uint64]tcpConnInfo)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if err := parseProcNetTCP(path, conns); err != nil {
			continue
		}
	}
	if len(conns) == 0 {
		return nil, nil
	}

	// Collect all socket inodes owned by any process fd.
	owned := make(map[uint64]bool)
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid <= 0 {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			var inode uint64
			fmt.Sscanf(target, "socket:[%d]", &inode)
			owned[inode] = true
		}
	}

	var findings []RootkitFinding
	for inode, info := range conns {
		if inode == 0 || owned[inode] {
			continue
		}
		// Only flag ESTABLISHED (01) and LISTEN (0A) — TIME_WAIT etc. are legitimately orphaned.
		if info.state != "01" && info.state != "0A" {
			continue
		}
		state := "ESTABLISHED"
		if info.state == "0A" {
			state = "LISTEN"
		}
		findings = append(findings, RootkitFinding{
			DetectionType: "orphaned_tcp_connection",
			Severity:      "high",
			ThreatScore:   0.80,
			Evidence: map[string]interface{}{
				"inode":  inode,
				"local":  info.local,
				"remote": info.remote,
				"state":  state,
			},
			Timestamp:   time.Now(),
			Remediation: fmt.Sprintf("%s socket inode %d has no owning process fd — possible hidden process or kernel-level backdoor.", state, inode),
		})
	}
	return findings, nil
}

// parseProcNetTCP reads /proc/net/tcp or /proc/net/tcp6 and populates a map of
// inode → connection info. Skips the header line.
func parseProcNetTCP(path string, out map[uint64]tcpConnInfo) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		// Fields: sl local_addr rem_addr state tx_queue:rx_queue tr:tm uid timeout inode ...
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		var inode uint64
		fmt.Sscanf(fields[9], "%d", &inode)
		out[inode] = tcpConnInfo{
			local:  fields[1],
			remote: fields[2],
			state:  fields[3],
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func procReadComm(pid int) string {
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(data))
}

func severityFromScoreRK(score float64) string {
	switch {
	case score >= 0.85:
		return "critical"
	case score >= 0.65:
		return "high"
	case score >= 0.40:
		return "medium"
	default:
		return "low"
	}
}
