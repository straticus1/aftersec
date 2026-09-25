//go:build linux

package forensics

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// PerformFullScan compares /proc views. A required view that cannot be read
// returns an error. Findings collected before that failure are still returned.
func (rd *RootkitDetector) PerformFullScan() ([]RootkitFinding, error) {
	var findings []RootkitFinding
	var failed error
	collect := func(f []RootkitFinding, err error) {
		findings = append(findings, f...)
		if err != nil && failed == nil {
			failed = err
		}
	}
	f, err := rd.detectHiddenProcesses()
	collect(f, err)
	f, err = rd.detectLDPreload()
	collect(f, err)
	f, err = rd.auditKernelModules()
	collect(f, err)
	f, err = rd.detectOrphanedConnections()
	collect(f, err)
	if logErr := rd.record(findings); logErr != nil && failed == nil {
		failed = logErr
	}
	return findings, failed
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
	visible := make(map[int]struct{}, len(entries))
	maxPID := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil && pid > 0 {
			visible[pid] = struct{}{}
			if pid > maxPID {
				maxPID = pid
			}
		}
	}
	if len(visible) == 0 {
		return nil, fmt.Errorf("process view is empty")
	}

	probeMax := 32768
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return nil, fmt.Errorf("process view is unavailable")
	}
	var pidMax int
	if _, err = fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pidMax); err != nil || pidMax <= 0 {
		return nil, fmt.Errorf("process view is unreadable")
	}
	if pidMax < probeMax {
		probeMax = pidMax
	}
	if maxPID+100 < probeMax {
		probeMax = maxPID + 100
	}

	var candidates []int
	for pid := 1; pid <= probeMax; pid++ {
		if _, ok := visible[pid]; ok {
			continue
		}
		if _, err = os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
			continue
		}
		candidates = append(candidates, pid)
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	second, err := procPIDSet()
	if err != nil {
		return nil, err
	}
	var findings []RootkitFinding
	for _, pid := range candidates {
		if _, ok := second[pid]; ok {
			continue
		}
		if _, err = os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
			continue
		}
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
			Remediation: fmt.Sprintf("PID %d is missing from /proc directory listing and still stat-accessible.", pid),
		})
	}
	return findings, nil
}

func procPIDSet() (map[int]struct{}, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("process view is unavailable")
	}
	pids := map[int]struct{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil && pid > 0 {
			pids[pid] = struct{}{}
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("process view is empty")
	}
	return pids, nil
}

// ── LD_PRELOAD injection ──────────────────────────────────────────────────────

func (rd *RootkitDetector) detectLDPreload() ([]RootkitFinding, error) {
	var findings []RootkitFinding

	data, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("preload view is unavailable")
	}
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' {
				continue
			}
			score := 0.85
			if suspiciousLibraryPath(line) {
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
				Remediation: "A system-wide preload is configured. Remove the entry after confirming it is unexpected.",
			})
		}
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return findings, fmt.Errorf("process view is unavailable")
	}
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
			if !suspiciousLibraryPath(libs) {
				continue
			}
			comm := procReadComm(pid)
			findings = append(findings, RootkitFinding{
				DetectionType: "ldpreload_injection",
				Severity:      "critical",
				ThreatScore:   0.95,
				Evidence: map[string]interface{}{
					"pid":       pid,
					"comm":      comm,
					"libraries": libs,
				},
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("PID %d has a preload library outside the operating-system library directories.", pid),
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

	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, fmt.Errorf("module view is unavailable")
	}
	sysModules := make(map[string]bool, len(entries))
	for _, e := range entries {
		sysModules[e.Name()] = true
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
		known := false
		lower := strings.ToLower(name)
		for _, rk := range knownRootkitModules {
			if strings.Contains(lower, rk) {
				known = true
				break
			}
		}
		inSys := sysModules[name]
		if !moduleNeedsReview(known, inSys) {
			continue
		}
		reasons := []string{}
		score := 0.8
		if known {
			reasons = append(reasons, "name matches a documented rootkit module")
			score = 0.95
		}
		if !inSys {
			reasons = append(reasons, "module is listed in /proc/modules and missing from /sys/module")
		}
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
			Remediation: "A kernel module disagrees with sysfs or matches a documented rootkit name. Inspect it before removing it.",
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
	saw := false
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		err := parseProcNetTCP(path, conns)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tcp view is unavailable")
		}
		saw = true
	}
	if !saw {
		return nil, fmt.Errorf("tcp view is unavailable")
	}
	if len(conns) == 0 {
		return nil, nil
	}

	owned := make(map[uint64]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("process view is unavailable")
	}
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
			return fmt.Errorf("tcp view is unreadable")
		}
		var inode uint64
		if _, err = fmt.Sscanf(fields[9], "%d", &inode); err != nil || inode == 0 {
			return fmt.Errorf("tcp view is unreadable")
		}
		out[inode] = tcpConnInfo{
			local:  fields[1],
			remote: fields[2],
			state:  fields[3],
		}
	}
	if err = scanner.Err(); err != nil {
		return fmt.Errorf("tcp view is unreadable")
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func procReadComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
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
