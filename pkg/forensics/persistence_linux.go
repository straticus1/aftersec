//go:build linux

package forensics

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type PersistenceFinding struct {
	PlistPath   string // config file path (unit file, crontab, .desktop, etc.)
	Program     string
	IsHidden    bool
	Authority   string
	ThreatScore ThreatScore
	Reason      string
}

// ScanPersistenceMechanisms scans Linux autostart locations for suspicious entries:
// systemd units, cron files, XDG autostart, init.d scripts, and rc.local.
func ScanPersistenceMechanisms() ([]PersistenceFinding, error) {
	home, _ := os.UserHomeDir()
	var out []PersistenceFinding
	out = append(out, scanSystemdUnits(home)...)
	out = append(out, scanCronFiles(home)...)
	out = append(out, scanXDGAutostart(home)...)
	out = append(out, scanInitD()...)
	out = append(out, scanRcLocal()...)
	return out, nil
}

// ── systemd ──────────────────────────────────────────────────────────────────

var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/usr/local/lib/systemd/system",
}

// execDirectives are the systemd [Service] keys that run binaries.
var execDirectives = map[string]bool{
	"ExecStart":    true,
	"ExecStartPre": true,
	"ExecStop":     true,
	"ExecReload":   true,
}

func scanSystemdUnits(home string) []PersistenceFinding {
	dirs := append(systemdUnitDirs,
		filepath.Join(home, ".config/systemd/user"),
		"/etc/systemd/user",
	)
	var findings []PersistenceFinding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			findings = append(findings, scanSystemdUnit(filepath.Join(dir, e.Name()))...)
		}
	}
	return findings
}

func scanSystemdUnit(path string) []PersistenceFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []PersistenceFinding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		if !execDirectives[strings.TrimSpace(line[:idx])] {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		val = strings.TrimLeft(val, "-+!@") // strip systemd modifiers
		prog := extractFirstToken(val)
		if prog == "" || prog[0] != '/' {
			continue
		}
		if pf := scoreLinuxPersistence(path, prog, "systemd"); pf != nil {
			findings = append(findings, *pf)
		}
	}
	return findings
}

// ── cron ─────────────────────────────────────────────────────────────────────

var cronDirs = []string{
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

func scanCronFiles(home string) []PersistenceFinding {
	var findings []PersistenceFinding

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				findings = append(findings, scanCronFile(filepath.Join(dir, e.Name()))...)
			}
		}
	}

	// System crontabs per user
	if entries, err := os.ReadDir("/var/spool/cron/crontabs"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				findings = append(findings, scanCronFile(filepath.Join("/var/spool/cron/crontabs", e.Name()))...)
			}
		}
	}

	// Current user's fallback crontab location
	if _, err := os.Stat(filepath.Join(home, ".crontab")); err == nil {
		findings = append(findings, scanCronFile(filepath.Join(home, ".crontab"))...)
	}

	return findings
}

func scanCronFile(path string) []PersistenceFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []PersistenceFinding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		// Skip env var assignments (no spaces, contains =)
		if !strings.ContainsAny(line, " \t") {
			continue
		}
		// Find first absolute-path token — works for both /etc/cron.d (has username field)
		// and user crontabs, and handles @reboot/@yearly etc. directives.
		for _, tok := range strings.Fields(line) {
			if len(tok) > 1 && tok[0] == '/' {
				if pf := scoreLinuxPersistence(path, tok, "cron"); pf != nil {
					findings = append(findings, *pf)
				}
				break
			}
		}
	}
	return findings
}

// ── XDG autostart ────────────────────────────────────────────────────────────

func scanXDGAutostart(home string) []PersistenceFinding {
	dirs := []string{
		"/etc/xdg/autostart",
		filepath.Join(home, ".config/autostart"),
	}
	var findings []PersistenceFinding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			findings = append(findings, scanDesktopFile(filepath.Join(dir, e.Name()))...)
		}
	}
	return findings
}

func scanDesktopFile(path string) []PersistenceFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []PersistenceFinding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Exec=") {
			continue
		}
		val := stripDesktopFieldCodes(strings.TrimPrefix(line, "Exec="))
		prog := extractFirstToken(val)
		if prog == "" || prog[0] != '/' {
			continue
		}
		if pf := scoreLinuxPersistence(path, prog, "XDG autostart"); pf != nil {
			findings = append(findings, *pf)
		}
	}
	return findings
}

// stripDesktopFieldCodes removes %f, %u, %F, etc. from .desktop Exec values.
func stripDesktopFieldCodes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+1 < len(s) {
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ── init.d and rc.local ───────────────────────────────────────────────────────

func scanInitD() []PersistenceFinding {
	entries, err := os.ReadDir("/etc/init.d")
	if err != nil {
		return nil
	}
	var findings []PersistenceFinding
	for _, e := range entries {
		if !e.IsDir() {
			findings = append(findings, scanShellScript(filepath.Join("/etc/init.d", e.Name()))...)
		}
	}
	return findings
}

func scanRcLocal() []PersistenceFinding {
	for _, path := range []string{"/etc/rc.local", "/etc/rc.d/rc.local"} {
		if _, err := os.Stat(path); err == nil {
			return scanShellScript(path)
		}
	}
	return nil
}

// scanShellScript finds absolute-path executable invocations in a shell script.
// It uses a conservative heuristic: look for tokens starting with / that aren't
// obviously config/log/device paths. One finding per line to avoid noise.
func scanShellScript(path string) []PersistenceFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []PersistenceFinding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		for _, tok := range strings.Fields(line) {
			tok = strings.TrimLeft(tok, "&|;(")
			if len(tok) < 3 || tok[0] != '/' {
				continue
			}
			// Skip obviously non-executable paths
			if strings.HasPrefix(tok, "/dev/") || strings.HasPrefix(tok, "/proc/") ||
				strings.HasPrefix(tok, "/sys/") || strings.HasSuffix(tok, ".conf") ||
				strings.HasSuffix(tok, ".log") || strings.HasSuffix(tok, ".pid") {
				continue
			}
			if pf := scoreLinuxPersistence(path, tok, "shell script"); pf != nil {
				findings = append(findings, *pf)
				break // one per line is enough for noisy shell scripts
			}
		}
	}
	return findings
}

// ── scoring ───────────────────────────────────────────────────────────────────

// scoreLinuxPersistence applies threat scoring to a program path found in a
// persistence config. Returns nil if nothing suspicious was found.
func scoreLinuxPersistence(configPath, program, source string) *PersistenceFinding {
	var reasons []string
	score := Safe

	// Hidden path component
	isHidden := false
	for _, part := range strings.Split(filepath.Clean(program), "/") {
		if strings.HasPrefix(part, ".") && part != "." {
			isHidden = true
			break
		}
	}
	if isHidden {
		score = Suspicious
		reasons = append(reasons, "binary runs from a hidden directory or has a hidden filename")
	}

	// Volatile storage
	if strings.HasPrefix(program, "/tmp") ||
		strings.HasPrefix(program, "/var/tmp") ||
		strings.HasPrefix(program, "/dev/shm") ||
		strings.HasPrefix(program, "/run/user") {
		score = Malicious
		reasons = append(reasons, "persistent payload launches from volatile temporary storage")
	}

	// File existence and attributes
	fi, err := os.Stat(program)
	var authority string
	if err != nil {
		if score < Suspicious {
			score = Suspicious
		}
		reasons = append(reasons, "binary does not exist on disk (possible cleaned-up dropper)")
		authority = "not found"
	} else {
		authority = fileOwner(fi)
		if fi.Mode()&0002 != 0 {
			if score < Suspicious {
				score = Suspicious
			}
			reasons = append(reasons, "binary is world-writable (trivial replacement attack vector)")
		}
		if fi.Mode()&os.ModeSetuid != 0 && !isSystemBin(program) {
			if score < Suspicious {
				score = Suspicious
			}
			reasons = append(reasons, "setuid binary outside standard system paths")
		}
	}

	if score == Safe {
		return nil
	}

	return &PersistenceFinding{
		PlistPath:   configPath,
		Program:     program,
		IsHidden:    isHidden,
		Authority:   authority,
		ThreatScore: score,
		Reason:      fmt.Sprintf("[%s] %s", source, strings.Join(reasons, "; ")),
	}
}

// fileOwner returns a human-readable owner string from a FileInfo.
func fileOwner(fi os.FileInfo) string {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown"
	}
	if stat.Uid == 0 {
		return "root"
	}
	return fmt.Sprintf("uid:%d", stat.Uid)
}

// isSystemBin returns true for paths that are expected to contain setuid binaries.
func isSystemBin(path string) bool {
	systemPrefixes := []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/"}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// extractFirstToken returns the first token from a value string, handling
// double-quoted paths like "/path/to/bin" arg1 arg2.
func extractFirstToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return ""
	}
	if s[0] == '"' {
		end := strings.IndexByte(s[1:], '"')
		if end >= 0 {
			return s[1 : end+1]
		}
	}
	fields := strings.Fields(s)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}
