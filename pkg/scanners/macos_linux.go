//go:build linux

package scanners

import (
	"fmt"
	"os"
	"strings"
	"time"

	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
)

// MacOSScanner is named for API compatibility with the darwin side.
// On Linux it runs the equivalent CIS benchmark checks.
type MacOSScanner struct {
	db storage.Manager
}

func NewMacOSScanner(db storage.Manager) *MacOSScanner {
	return &MacOSScanner{db: db}
}

func (s *MacOSScanner) Scan(progress func(float64, string)) (*core.SecurityState, error) {
	state := &core.SecurityState{Timestamp: time.Now()}

	const totalSteps = 16.0
	step := 0.0
	addFinding := func(f core.Finding) {
		state.Findings = append(state.Findings, f)
		step++
		if progress != nil {
			progress(step/totalSteps, fmt.Sprintf("Analyzed: %s...", f.Name))
		}
	}

	if progress != nil {
		progress(0.0, "Initializing Linux CIS benchmark scan...")
	}

	// 1. Firewall (ufw / iptables) — CIS 3.5.3.1
	ufwActive := false
	ufwVal := "inactive"
	if data, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil && strings.TrimSpace(string(data)) != "" {
		ufwActive = true
		ufwVal = "active (" + strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", ", ") + ")"
	}
	addFinding(core.Finding{
		Category:          "Network Security",
		Name:              "Firewall (iptables/ufw)",
		Description:       "Checks that a netfilter-based firewall has active rules tables.",
		Severity:          core.VeryHigh,
		CurrentVal:        ufwVal,
		ExpectedVal:       "active",
		CISBenchmark:      "3.5.3.1",
		RemediationScript: "ufw enable",
		LogContext:        ufwVal,
		Passed:            ufwActive,
	})

	// 2. AppArmor — CIS 1.6.1.1
	aaEnabled := false
	aaVal := "not loaded"
	if _, err := os.Stat("/sys/module/apparmor"); err == nil {
		if data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err == nil {
			aaEnabled = true
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			aaVal = fmt.Sprintf("loaded, %d profiles", len(lines))
		} else {
			aaVal = "module loaded, no profiles"
		}
	}
	addFinding(core.Finding{
		Category:          "System Capabilities",
		Name:              "AppArmor Status",
		Description:       "Verifies AppArmor MAC framework is loaded and has enforcement profiles.",
		Severity:          core.High,
		CurrentVal:        aaVal,
		ExpectedVal:       "loaded with profiles",
		CISBenchmark:      "1.6.1.1",
		RemediationScript: "apt-get install apparmor apparmor-profiles && systemctl enable apparmor",
		LogContext:        aaVal,
		Passed:            aaEnabled,
	})

	// 3. auditd running — CIS 4.1.1.1
	auditRunning := false
	auditVal := "not running"
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", e.Name()))
			if strings.TrimSpace(string(comm)) == "auditd" {
				auditRunning = true
				auditVal = "running"
				break
			}
		}
	}
	addFinding(core.Finding{
		Category:          "Deep System & Kernel",
		Name:              "auditd Logging Daemon",
		Description:       "Verifies the Linux audit daemon is actively running.",
		Severity:          core.High,
		CurrentVal:        auditVal,
		ExpectedVal:       "running",
		CISBenchmark:      "4.1.1.1",
		RemediationScript: "apt-get install auditd && systemctl enable --now auditd",
		LogContext:        auditVal,
		Passed:            auditRunning,
	})

	// 4. SSH PasswordAuthentication disabled — CIS 5.2.8
	sshData, _ := os.ReadFile("/etc/ssh/sshd_config")
	sshLines := strings.Split(string(sshData), "\n")
	sshPwAuth := "unset (default: yes)"
	sshPwPassed := false
	for _, line := range sshLines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "passwordauthentication") && line[0] != '#' {
			sshPwAuth = line
			sshPwPassed = strings.Contains(strings.ToLower(line), "no")
			break
		}
	}
	addFinding(core.Finding{
		Category:          "Network Security",
		Name:              "SSH Password Authentication",
		Description:       "Checks if SSH password auth is disabled in sshd_config.",
		Severity:          core.High,
		CurrentVal:        sshPwAuth,
		ExpectedVal:       "PasswordAuthentication no",
		CISBenchmark:      "5.2.8",
		RemediationScript: "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd",
		LogContext:        sshPwAuth,
		Passed:            sshPwPassed,
	})

	// 5. SSH PermitRootLogin disabled — CIS 5.2.10
	sshRootLogin := "unset (default: prohibit-password)"
	sshRootPassed := true // prohibit-password is the safe default
	for _, line := range sshLines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "permitrootlogin") && line[0] != '#' {
			sshRootLogin = line
			lower := strings.ToLower(line)
			sshRootPassed = strings.Contains(lower, "no") || strings.Contains(lower, "prohibit-password")
			break
		}
	}
	addFinding(core.Finding{
		Category:          "Network Security",
		Name:              "SSH PermitRootLogin",
		Description:       "Checks that direct root SSH login is disabled.",
		Severity:          core.VeryHigh,
		CurrentVal:        sshRootLogin,
		ExpectedVal:       "no or prohibit-password",
		CISBenchmark:      "5.2.10",
		RemediationScript: "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd",
		LogContext:        sshRootLogin,
		Passed:            sshRootPassed,
	})

	// 6. SSH MaxAuthTries — CIS 5.2.7
	sshMaxAuth := "unset (default: 6)"
	sshMaxPassed := false
	for _, line := range sshLines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "maxauthtries") && line[0] != '#' {
			sshMaxAuth = line
			var n int
			fmt.Sscanf(strings.Fields(line)[1], "%d", &n)
			sshMaxPassed = n > 0 && n <= 4
			break
		}
	}
	addFinding(core.Finding{
		Category:          "Network Security",
		Name:              "SSH MaxAuthTries",
		Description:       "Limits SSH authentication attempts to reduce brute-force exposure.",
		Severity:          core.Med,
		CurrentVal:        sshMaxAuth,
		ExpectedVal:       "<= 4",
		CISBenchmark:      "5.2.7",
		RemediationScript: "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl restart sshd",
		LogContext:        sshMaxAuth,
		Passed:            sshMaxPassed,
	})

	// 7. Sudoers NOPASSWD audit — CIS 5.3.x
	sudoVal := "No NOPASSWD found"
	sudoPassed := true
	for _, path := range []string{"/etc/sudoers"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "NOPASSWD") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				sudoPassed = false
				sudoVal = "NOPASSWD entries found"
				break
			}
		}
	}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			data, _ := os.ReadFile(fmt.Sprintf("/etc/sudoers.d/%s", e.Name()))
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "NOPASSWD") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					sudoPassed = false
					sudoVal = "NOPASSWD entries found in sudoers.d"
				}
			}
		}
	}
	addFinding(core.Finding{
		Category:    "Identity & Access",
		Name:        "Sudoers NOPASSWD Audit",
		Description: "Checks if any accounts can elevate privileges without a password.",
		Severity:    core.High,
		CurrentVal:  sudoVal,
		ExpectedVal: "No NOPASSWD found",
		CISBenchmark: "5.3.6",
		LogContext:  sudoVal,
		Passed:      sudoPassed,
	})

	// 8. Core dumps disabled — CIS 1.5.1
	coreDump := "unknown"
	corePassed := false
	if data, err := os.ReadFile("/proc/sys/kernel/core_pattern"); err == nil {
		pat := strings.TrimSpace(string(data))
		coreDump = pat
		corePassed = pat == "|/bin/false" || pat == "/dev/null" || pat == ""
	}
	addFinding(core.Finding{
		Category:          "System Capabilities",
		Name:              "Core Dumps Disabled",
		Description:       "Prevents core dumps that may expose sensitive memory contents.",
		Severity:          core.Med,
		CurrentVal:        coreDump,
		ExpectedVal:       "|/bin/false or /dev/null",
		CISBenchmark:      "1.5.1",
		RemediationScript: "echo '* hard core 0' >> /etc/security/limits.conf && echo 'kernel.core_pattern=/dev/null' >> /etc/sysctl.d/99-hardening.conf && sysctl -p",
		LogContext:        coreDump,
		Passed:            corePassed,
	})

	// 9. Password quality policy — CIS 5.4.1
	pwqVal := "not configured"
	pwqPassed := false
	if data, err := os.ReadFile("/etc/security/pwquality.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "minlen") && line[0] != '#' {
				pwqVal = line
				var n int
				fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "minlen")), "= %d", &n)
				if n == 0 {
					fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "minlen")), "%d", &n)
				}
				pwqPassed = n >= 14
				break
			}
		}
		if pwqVal == "not configured" {
			pwqVal = "file exists but minlen not set"
		}
	}
	addFinding(core.Finding{
		Category:          "Identity & Access",
		Name:              "Password Complexity Policy",
		Description:       "Checks /etc/security/pwquality.conf for a minimum password length of 14+.",
		Severity:          core.High,
		CurrentVal:        pwqVal,
		ExpectedVal:       "minlen >= 14",
		CISBenchmark:      "5.4.1",
		RemediationScript: "apt-get install libpam-pwquality && echo 'minlen = 14' >> /etc/security/pwquality.conf",
		LogContext:        pwqVal,
		Passed:            pwqPassed,
	})

	// 10. Automatic security updates — CIS 1.9
	autoUpdateVal := "not configured"
	autoUpdatePassed := false
	for _, path := range []string{
		"/etc/apt/apt.conf.d/20auto-upgrades",
		"/etc/apt/apt.conf.d/50unattended-upgrades",
	} {
		if data, err := os.ReadFile(path); err == nil {
			content := string(data)
			if strings.Contains(content, `"1"`) || strings.Contains(content, `"true"`) {
				autoUpdatePassed = true
				autoUpdateVal = path + " configured"
				break
			}
		}
	}
	if !autoUpdatePassed {
		if _, err := os.Stat("/etc/dnf/automatic.conf"); err == nil {
			autoUpdatePassed = true
			autoUpdateVal = "dnf-automatic configured"
		}
	}
	addFinding(core.Finding{
		Category:          "System Maintenance",
		Name:              "Automatic Security Updates",
		Description:       "Checks for unattended-upgrades or dnf-automatic to apply security patches.",
		Severity:          core.High,
		CurrentVal:        autoUpdateVal,
		ExpectedVal:       "configured",
		CISBenchmark:      "1.9",
		RemediationScript: "apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
		LogContext:        autoUpdateVal,
		Passed:            autoUpdatePassed,
	})

	// 11. Syslog/journald running — CIS 4.2
	syslogRunning := false
	syslogVal := "not running"
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", e.Name()))
			name := strings.TrimSpace(string(comm))
			if name == "rsyslogd" || name == "syslogd" || name == "journald" || name == "systemd-journal" {
				syslogRunning = true
				syslogVal = "running (" + name + ")"
				break
			}
		}
	}
	addFinding(core.Finding{
		Category:          "Deep System & Kernel",
		Name:              "System Logging Daemon",
		Description:       "Verifies rsyslog or journald is running for event logging.",
		Severity:          core.High,
		CurrentVal:        syslogVal,
		ExpectedVal:       "running",
		CISBenchmark:      "4.2.1.1",
		RemediationScript: "apt-get install rsyslog && systemctl enable --now rsyslog",
		LogContext:        syslogVal,
		Passed:            syslogRunning,
	})

	// 12. IPv6 disabled if unused — CIS 3.1.1 (log only; not universally correct to disable)
	ipv6Data, _ := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	ipv6Disabled := strings.TrimSpace(string(ipv6Data)) == "1"
	ipv6Val := "enabled"
	if ipv6Disabled {
		ipv6Val = "disabled"
	}
	addFinding(core.Finding{
		Category:    "Network Security",
		Name:        "IPv6 Disable Status",
		Description: "Logs whether IPv6 is disabled. Disable if not in use to reduce attack surface.",
		Severity:    core.LogOnly,
		CurrentVal:  ipv6Val,
		ExpectedVal: "disabled if not required",
		CISBenchmark: "3.1.1",
		LogContext:  ipv6Val,
		Passed:      true,
	})

	// 13. Time synchronization — CIS 2.1.1
	timeSyncRunning := false
	timeSyncVal := "not running"
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", e.Name()))
			name := strings.TrimSpace(string(comm))
			if name == "chronyd" || name == "ntpd" || name == "systemd-timesyn" {
				timeSyncRunning = true
				timeSyncVal = "running (" + name + ")"
				break
			}
		}
	}
	addFinding(core.Finding{
		Category:          "System Maintenance",
		Name:              "Time Synchronization",
		Description:       "Verifies chrony, ntpd, or systemd-timesyncd is running for accurate timestamps.",
		Severity:          core.Med,
		CurrentVal:        timeSyncVal,
		ExpectedVal:       "running",
		CISBenchmark:      "2.1.1",
		RemediationScript: "apt-get install chrony && systemctl enable --now chrony",
		LogContext:        timeSyncVal,
		Passed:            timeSyncRunning,
	})

	// 14. Listening TCP ports — log only
	listenPorts := collectListenPorts()
	addFinding(core.Finding{
		Category:    "Advanced Network Defense",
		Name:        "Listening TCP Ports",
		Description: "Lists all locally listening TCP ports to find rogue services.",
		Severity:    core.LogOnly,
		CurrentVal:  fmt.Sprintf("%d listening ports", len(listenPorts)),
		ExpectedVal: "N/A",
		CISBenchmark: "N/A",
		LogContext:  strings.Join(listenPorts, ", "),
		Passed:      true,
	})

	// 15. DNS configuration — log only
	dnsVal := "not configured"
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		var servers []string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "nameserver") {
				servers = append(servers, strings.Fields(line)[1])
			}
		}
		if len(servers) > 0 {
			dnsVal = strings.Join(servers, ", ")
		}
	}
	addFinding(core.Finding{
		Category:    "Advanced Network Defense",
		Name:        "Configured Nameservers",
		Description: "Audits DNS configuration for rogue or unauthorized forwarders.",
		Severity:    core.LogOnly,
		CurrentVal:  dnsVal,
		ExpectedVal: "known healthy DNS",
		CISBenchmark: "N/A",
		LogContext:  dnsVal,
		Passed:      true,
	})

	// 16. Delegate to cross-platform deep scanners
	ScanSecrets(addFinding)
	ScanVulnerabilities(addFinding)

	return state, nil
}

// collectListenPorts reads /proc/net/tcp and tcp6 and returns hex local addresses
// for sockets in LISTEN state (state 0A).
func collectListenPorts() []string {
	var ports []string
	seen := make(map[string]bool)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			addr := fields[1] // hex local_address:port
			if !seen[addr] {
				seen[addr] = true
				ports = append(ports, addr)
			}
		}
	}
	return ports
}
