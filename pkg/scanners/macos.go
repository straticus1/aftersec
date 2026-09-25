//go:build darwin

package scanners

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"aftersec/pkg/plugins"
	"fmt"
	"strings"
	"time"
)

type MacOSScanner struct {
	db      storage.Manager
	Profile string
}

func NewMacOSScanner(db storage.Manager) *MacOSScanner {
	return &MacOSScanner{db: db}
}

func (s *MacOSScanner) Scan(progress func(percent float64, message string)) (*core.SecurityState, error) {
	if err := ValidateProfile(s.Profile); err != nil {
		return nil, err
	}
	state := &core.SecurityState{
		Timestamp: time.Now(),
	}

	totalSteps := 26.0 + float64(plugins.NumStarlarkRules())
	step := 0.0

	addFinding := func(finding core.Finding) {
		state.Findings = append(state.Findings, finding)
		step++
		if progress != nil {
			progress(step/totalSteps, fmt.Sprintf("Analyzed: %s...", finding.Name))
		}
		if s.Profile != "quick" {
			time.Sleep(250 * time.Millisecond)
		}
	}

	if progress != nil {
		progress(0.0, "Initializing scan engines...")
	}

	sip := RunProbe(5*time.Second, "csrutil", "status")
	if !sip.Ran() || sip.Exit != 0 {
		addFinding(probeFailed("System Integrity Protection (SIP)", "enabled", sip))
	} else {
		sipEnabled := strings.Contains(strings.ToLower(sip.Output), "enabled")
		currSipVal := "disabled"
		if sipEnabled {
			currSipVal = "enabled"
		}
		addFinding(core.Finding{
			Category:     "System Capabilities",
			Name:         "System Integrity Protection (SIP)",
			Description:  "Protects core system files and processes.",
			Severity:     core.VeryHigh,
			CurrentVal:   currSipVal,
			ExpectedVal:  "enabled",
			CISBenchmark: "2.12",
			LogContext:   sip.Output,
			Passed:       sipEnabled,
		})
	}

	alf := RunProbe(5*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if !alf.Ran() || alf.Exit != 0 {
		addFinding(probeFailed("Application Layer Firewall (ALF)", "enabled", alf))
	} else {
		alfEnabled := strings.Contains(strings.ToLower(alf.Output), "enabled")
		currAlfVal := "disabled"
		if alfEnabled {
			currAlfVal = "enabled"
		}
		addFinding(core.Finding{
			Category:          "Network Security",
			Name:              "Application Layer Firewall (ALF)",
			Description:       "Controls connections on a per-application basis.",
			Severity:          core.High,
			CurrentVal:        currAlfVal,
			ExpectedVal:       "enabled",
			CISBenchmark:      "2.5.1",
			RemediationScript: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
			LogContext:        alf.Output,
			Passed:            alfEnabled,
		})
	}

	guest := RunProbe(5*time.Second, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
	if !guest.Ran() {
		addFinding(probeFailed("Guest Account Login", "0", guest))
	} else {
		addFinding(core.Finding{
			Category:          "Defaults",
			Name:              "Guest Account Login",
			Description:       "Checks if the Guest Account is disabled.",
			Severity:          core.Med,
			CurrentVal:        guest.Output,
			ExpectedVal:       "0",
			CISBenchmark:      "5.1",
			RemediationScript: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool NO",
			LogContext:        guest.Output,
			Passed:            guest.Output == "0",
		})
	}

	// 4. Insecure Network Settings: SSH Password Authentication
	ssh := RunProbe(5*time.Second, "grep", "^PasswordAuthentication", "/etc/ssh/sshd_config")
	if !ssh.Ran() || ssh.Exit > 1 {
		addFinding(probeFailed("SSH Password Authentication", "PasswordAuthentication no (or unset)", ssh))
	} else {
		sshStr := ssh.Output
		if sshStr == "" {
			sshStr = "unset"
		}
		sshPassed := ssh.Exit == 1 || !strings.Contains(strings.ToLower(ssh.Output), "yes")
		addFinding(core.Finding{
			Category:          "Network Security",
			Name:              "SSH Password Authentication",
			Description:       "Checks if SSH password auth is disabled in sshd_config.",
			Severity:          core.High,
			CurrentVal:        sshStr,
			ExpectedVal:       "PasswordAuthentication no (or unset)",
			CISBenchmark:      "2.3.1",
			RemediationScript: "sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && launchctl stop com.openssh.sshd 2>/dev/null || true",
			LogContext:        ssh.Output,
			Passed:            sshPassed,
		})
	}

	// 5. Gatekeeper (spctl)
	spctl := RunProbe(5*time.Second, "spctl", "--status")
	if !spctl.Ran() || spctl.Exit != 0 {
		addFinding(probeFailed("Gatekeeper Status", "assessments enabled", spctl))
	} else {
		spctlStr := spctl.Output
		spctlPassed := strings.Contains(spctlStr, "assessments enabled")
		addFinding(core.Finding{
			Category:          "System Capabilities",
			Name:              "Gatekeeper Status",
			Description:       "Checks if signature assessments are enabled.",
			Severity:          core.VeryHigh,
			CurrentVal:        spctlStr,
			ExpectedVal:       "assessments enabled",
			CISBenchmark:      "2.9",
			RemediationScript: "spctl --master-enable",
			LogContext:        spctlStr,
			Passed:            spctlPassed,
		})
	}

	// 6. Check FileVault Encryption
	fv := RunProbe(5*time.Second, "fdesetup", "status")
	if !fv.Ran() || fv.Exit != 0 {
		addFinding(probeFailed("FileVault Encryption", "FileVault is On.", fv))
	} else {
		fvStr := fv.Output
		fvPassed := strings.Contains(fvStr, "FileVault is On")
		addFinding(core.Finding{
			Category:     "Data Protection",
			Name:         "FileVault Encryption",
			Description:  "Ensures the boot volume is encrypted at rest.",
			Severity:     core.VeryHigh,
			CurrentVal:   fvStr,
			ExpectedVal:  "FileVault is On.",
			CISBenchmark: "2.7.1",
			LogContext:   fvStr,
			Passed:       fvPassed,
		})
	}

	sl := RunProbe(5*time.Second, "defaults", "read", "com.apple.screensaver", "askForPassword")
	if !sl.Ran() {
		addFinding(probeFailed("Screen Lock Requirement", "1", sl))
	} else {
		addFinding(core.Finding{
			Category:          "Authentication",
			Name:              "Screen Lock Requirement",
			Description:       "Ensures screen locks immediately and requires password to wake.",
			Severity:          core.High,
			CurrentVal:        sl.Output,
			ExpectedVal:       "1",
			CISBenchmark:      "2.8.2",
			RemediationScript: "defaults write com.apple.screensaver askForPassword -int 1",
			LogContext:        sl.Output,
			Passed:            sl.Output == "1",
		})
	}

	rae := RunProbe(5*time.Second, "systemsetup", "-getremoteappleevents")
	if !rae.Ran() {
		addFinding(probeFailed("Remote Apple Events", "Remote Apple Events: Off", rae))
	} else {
		addFinding(core.Finding{
			Category:          "System Capabilities",
			Name:              "Remote Apple Events",
			Description:       "Checks if Remote Apple Events are disabled to prevent remote execution.",
			Severity:          core.Med,
			CurrentVal:        rae.Output,
			ExpectedVal:       "Remote Apple Events: Off",
			CISBenchmark:      "2.1.2",
			RemediationScript: "systemsetup -setremoteappleevents off",
			LogContext:        rae.Output,
			Passed:            strings.Contains(rae.Output, "Off"),
		})
	}

	rl := RunProbe(5*time.Second, "systemsetup", "-getremotelogin")
	if !rl.Ran() {
		addFinding(probeFailed("Remote Login (SSH Admin)", "Remote Login: Off", rl))
	} else {
		addFinding(core.Finding{
			Category:          "Network Security",
			Name:              "Remote Login (SSH Admin)",
			Description:       "Checks if the primary SSH service (Remote Login) is disabled system-wide.",
			Severity:          core.High,
			CurrentVal:        rl.Output,
			ExpectedVal:       "Remote Login: Off",
			CISBenchmark:      "2.4",
			RemediationScript: "systemsetup -setremotelogin off",
			LogContext:        rl.Output,
			Passed:            strings.Contains(rl.Output, "Off"),
		})
	}

	ad := RunProbe(5*time.Second, "defaults", "read", "com.apple.NetworkBrowser", "DisableAirDrop")
	if !ad.Ran() {
		addFinding(probeFailed("Disable AirDrop", "1", ad))
	} else {
		addFinding(core.Finding{
			Category:          "Network Security",
			Name:              "Disable AirDrop",
			Description:       "Ensures AirDrop is explicitly disabled (DisableAirDrop=1) for strict security.",
			Severity:          core.Low,
			CurrentVal:        ad.Output,
			ExpectedVal:       "1",
			CISBenchmark:      "2.1.1",
			RemediationScript: "defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES",
			LogContext:        ad.Output,
			Passed:            ad.Output == "1",
		})
	}

	// 11. Automatic Updates
	au := RunProbe(5*time.Second, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
	if !au.Ran() {
		addFinding(probeFailed("Automatic Software Updates", "1", au))
	} else {
		auStr := au.Output
		auPassed := auStr == "1"
		addFinding(core.Finding{
			Category:          "System Maintenance",
			Name:              "Automatic Software Updates",
			Description:       "Checks if macOS is configured to automatically check for updates.",
			Severity:          core.High,
			CurrentVal:        auStr,
			ExpectedVal:       "1 (or default)",
			CISBenchmark:      "1.1",
			RemediationScript: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool YES",
			LogContext:        auStr,
			Passed:            auPassed,
		})
	}

	// 12. Check XProtect Version
	xp := RunProbe(5*time.Second, "defaults", "read", "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta", "Version")
	if !xp.Ran() || xp.Exit != 0 {
		addFinding(probeFailed("XProtect Definitions", "a version string", xp))
	} else {
		addFinding(core.Finding{
			Category:    "Threat Intelligence",
			Name:        "XProtect Definitions",
			Description: "Logs the current version of the built-in XProtect Yara signatures.",
			Severity:    core.LogOnly,
			CurrentVal:  xp.Output,
			ExpectedVal: "N/A",
			LogContext:  xp.Output,
			Passed:      true,
		})
	}

	// 13. Active Network Interfaces
	ifaces := RunProbe(5*time.Second, "ifconfig", "-a")
	if !ifaces.Ran() || ifaces.Exit != 0 {
		addFinding(probeFailed("Active Network Interfaces", "interface list", ifaces))
	} else {
		addFinding(core.Finding{
			Category:    "Troubleshooting",
			Name:        "Active Network Interfaces",
			Description: "Lists all standard network interfaces for auditing.",
			Severity:    core.LogOnly,
			CurrentVal:  "Collected",
			ExpectedVal: "N/A",
			LogContext:  ifaces.Output,
			Passed:      true,
		})
	}

	// 14. Sudoers NOPASSWD Audit
	sudo := RunProbe(5*time.Second, "grep", "-R", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d")
	if !sudo.Ran() || sudo.Exit > 1 {
		addFinding(probeFailed("Sudoers NOPASSWD Audit", "No NOPASSWD found", sudo))
	} else {
		sudoStr := sudo.Output
		sudoPassed := sudo.Exit == 1 || sudoStr == ""
		addFinding(core.Finding{
			Category:    "Identity & Access",
			Name:        "Sudoers NOPASSWD Audit",
			Description: "Checks if any accounts can elevate privileges without a password.",
			Severity:    core.High,
			CurrentVal: func() string {
				if sudoPassed {
					return "No NOPASSWD found"
				}
				return "Found NOPASSWD entries"
			}(),
			ExpectedVal: "No NOPASSWD found",
			LogContext:  sudoStr,
			Passed:      sudoPassed,
		})
	}

	// 15. Admin Account Count
	admin := RunProbe(5*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	if !admin.Ran() || admin.Exit != 0 {
		addFinding(probeFailed("Admin Account Count", "<= 2 admins", admin))
	} else {
		adminStr := admin.Output
		adminCount := len(strings.Fields(adminStr)) - 1 // subtract "GroupMembership:"
		if adminCount < 0 {
			adminCount = 0
		}
		adminPassed := adminCount <= 2
		addFinding(core.Finding{
			Category:    "Identity & Access",
			Name:        "Admin Account Count",
			Description: "Ensures the number of local Administrators does not exceed 2.",
			Severity:    core.Med,
			CurrentVal:  fmt.Sprintf("%d admins", adminCount),
			ExpectedVal: "<= 2 admins",
			LogContext:  adminStr,
			Passed:      adminPassed,
		})
	}

	// 16. Password Policy Strength
	pw := RunProbe(5*time.Second, "pwpolicy", "-getaccountpolicies")
	if !pw.Ran() {
		addFinding(probeFailed("Global Password Policy", "Configured", pw))
	} else {
		pwStr := pw.Output
		pwPassed := pw.Exit == 0 && !strings.Contains(pwStr, "Error") && strings.Contains(pwStr, "policy")
		addFinding(core.Finding{
			Category:    "Identity & Access",
			Name:        "Global Password Policy",
			Description: "Verifies if a global password complexity policy is enforced.",
			Severity:    core.High,
			CurrentVal: func() string {
				if pwPassed {
					return "Configured"
				}
				return "Not Configured"
			}(),
			ExpectedVal: "Configured",
			LogContext:  pwStr,
			Passed:      pwPassed,
		})
	}

	// 17. Non-Apple Kernel Extensions (Kexts)
	kext := RunProbe(5*time.Second, "kextstat")
	if !kext.Ran() || kext.Exit != 0 {
		addFinding(probeFailed("Non-Apple Kernel Extensions", "0 found", kext))
	} else {
		var third []string
		for _, line := range strings.Split(kext.Output, "\n") {
			if strings.TrimSpace(line) == "" || strings.Contains(line, "com.apple") || strings.HasPrefix(line, "Index") {
				continue
			}
			third = append(third, line)
		}
		kextStr := strings.Join(third, "\n")
		kextPassed := kextStr == ""
		addFinding(core.Finding{
			Category:    "Deep System & Kernel",
			Name:        "Non-Apple Kernel Extensions",
			Description: "Checks for legacy or third-party kernel extensions loaded into Ring-0.",
			Severity:    core.Med,
			CurrentVal: func() string {
				if kextPassed {
					return "0 found"
				}
				return "Third-party Kexts Loaded"
			}(),
			ExpectedVal: "0 found",
			LogContext:  kextStr,
			Passed:      kextPassed,
		})
	}

	// 18. Auditd Logging Status
	audit := RunProbe(5*time.Second, "ps", "-ax", "-o", "comm=")
	if !audit.Ran() || audit.Exit != 0 {
		addFinding(probeFailed("OpenBSM Auditd Status", "Running", audit))
	} else {
		auditPassed := false
		for _, line := range strings.Split(audit.Output, "\n") {
			if strings.TrimSpace(line) == "auditd" || strings.HasSuffix(strings.TrimSpace(line), "/auditd") {
				auditPassed = true
				break
			}
		}
		auditStr := "Not Running"
		if auditPassed {
			auditStr = "Running"
		}
		addFinding(core.Finding{
			Category:    "Deep System & Kernel",
			Name:        "OpenBSM Auditd Status",
			Description: "Verifies the macOS auditd daemon is actively running and logging events.",
			Severity:    core.High,
			CurrentVal:  auditStr,
			ExpectedVal: "Running",
			LogContext:  auditStr,
			Passed:      auditPassed,
		})
	}

	// 19. Safari Fraudulent Website Warning
	safari := RunProbe(5*time.Second, "defaults", "read", "com.apple.Safari", "WarnAboutFraudulentWebsites")
	if !safari.Ran() {
		addFinding(probeFailed("Safari Fraud Warning", "1", safari))
	} else {
		safariStr := safari.Output
		safariPassed := safariStr == "1"
		addFinding(core.Finding{
			Category:          "Application Security",
			Name:              "Safari Fraud Warning",
			Description:       "Ensures Safari 'Warn about fraudulent websites' feature is enabled.",
			Severity:          core.Med,
			CurrentVal:        safariStr,
			ExpectedVal:       "1",
			LogContext:        safariStr,
			RemediationScript: "defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool YES",
			Passed:            safariPassed,
		})
	}

	// 20. TCC Full Disk Access Audit
	tccPath := "/Library/Application Support/com.apple.TCC/TCC.db"
	tcc := RunProbe(5*time.Second, "sqlite3", tccPath, "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles'")
	if !tcc.Ran() {
		addFinding(probeFailed("TCC Full Disk Access Audit", "Review manually", tcc))
	} else {
		tccStr := tcc.Output
		tccPassed := tcc.Exit == 0 && !strings.Contains(tccStr, "unable to open database file") && !strings.Contains(tccStr, "authorization denied")
		tccVal := "Audited"
		if !tccPassed {
			tccVal = "Needs Full Disk Access to Audit TCC"
		}
		addFinding(core.Finding{
			Category:    "Application Security",
			Name:        "TCC Full Disk Access Audit",
			Description: "Audits binaries holding Full Disk Access. (Requires the scanner to have FDA).",
			Severity:    core.LogOnly,
			CurrentVal:  tccVal,
			ExpectedVal: "Review manually",
			LogContext:  tccStr,
			Passed:      tccPassed,
		})
	}

	// 21. Listening Network Ports
	lsof := RunProbe(5*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if !lsof.Ran() || lsof.Exit > 1 {
		addFinding(probeFailed("Listening Network Ports", "a port list", lsof))
	} else {
		addFinding(core.Finding{
			Category:    "Advanced Network Defense",
			Name:        "Listening Network Ports",
			Description: "Lists all locally listening TCP ports to find rogue services.",
			Severity:    core.LogOnly,
			CurrentVal:  "Collected",
			ExpectedVal: "N/A",
			LogContext:  lsof.Output,
			Passed:      true,
		})
	}

	// 22. System DNS Configuration
	dns := RunProbe(5*time.Second, "scutil", "--dns")
	if !dns.Ran() || dns.Exit != 0 {
		addFinding(probeFailed("Configured Nameservers", "Known healthy DNS", dns))
	} else {
		var servers []string
		for _, line := range strings.Split(dns.Output, "\n") {
			if strings.Contains(line, "nameserver") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					servers = append(servers, fields[len(fields)-1])
				}
			}
		}
		dnsStr := strings.Join(servers, " , ")
		dnsPassed := dnsStr != ""
		addFinding(core.Finding{
			Category:    "Advanced Network Defense",
			Name:        "Configured Nameservers",
			Description: "Audits DNS configuration for rogue or unauthorized forwarders.",
			Severity:    core.LogOnly,
			CurrentVal:  "Collected",
			ExpectedVal: "Known healthy DNS",
			LogContext:  strings.ReplaceAll(dnsStr, "\n", " , "),
			Passed:      dnsPassed,
		})
	}

	// 23. Captive Portal Bypass
	cp := RunProbe(5*time.Second, "defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.captive.control", "Active")
	if !cp.Ran() {
		addFinding(probeFailed("Captive Portal Automatic Login", "Disabled (0)", cp))
	} else {
		cpStr := cp.Output
		cpPassed := cpStr == "0"
		addFinding(core.Finding{
			Category:    "Advanced Network Defense",
			Name:        "Captive Portal Automatic Login",
			Description: "Checks if auto-login for captive portals is disabled to prevent MITM.",
			Severity:    core.Low,
			CurrentVal: func() string {
				if cpStr == "0" {
					return "Disabled"
				}
				return "Enabled"
			}(),
			ExpectedVal:       "Disabled (0)",
			LogContext:        cpStr,
			RemediationScript: "defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -int 0",
			Passed:            cpPassed,
		})
	}

	if s.Profile != "quick" {
		ScanSecrets(addFinding)
		ScanVulnerabilities(addFinding)
		ScanMalware(addFinding)
		ScanAgentSurface(addFinding)
		ScanArtifacts(addFinding)
		plugins.ScanStarlark(s.db, addFinding)
	}

	return state, nil
}
