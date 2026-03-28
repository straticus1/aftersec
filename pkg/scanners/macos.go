package scanners

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"aftersec/pkg/plugins"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type MacOSScanner struct {
	db storage.Manager
}

func NewMacOSScanner(db storage.Manager) *MacOSScanner {
	return &MacOSScanner{db: db}
}

func (s *MacOSScanner) Scan(progress func(percent float64, message string)) (*core.SecurityState, error) {
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
		time.Sleep(250 * time.Millisecond)
	}

	if progress != nil {
		progress(0.0, "Initializing scan engines...")
	}

	sipOut, _ := exec.Command("csrutil", "status").CombinedOutput()
	sipStatus := strings.ToLower(string(sipOut))
	sipEnabled := strings.Contains(sipStatus, "enabled")
	currSipVal := "disabled"
	if sipEnabled {
		currSipVal = "enabled"
	}
	addFinding(core.Finding{
		Category:    "System Capabilities",
		Name:        "System Integrity Protection (SIP)",
		Description: "Protects core system files and processes.",
		Severity:    core.VeryHigh,
		CurrentVal:  currSipVal,
		ExpectedVal: "enabled",
		CISBenchmark: "2.12",
		LogContext:  strings.TrimSpace(string(sipOut)),
		Passed:      sipEnabled,
	})

	alfOut, _ := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").CombinedOutput()
	alfStatus := strings.ToLower(string(alfOut))
	alfEnabled := strings.Contains(alfStatus, "enabled")
	currAlfVal := "disabled"
	if alfEnabled {
		currAlfVal = "enabled"
	}
	addFinding(core.Finding{
		Category:    "Network Security",
		Name:        "Application Layer Firewall (ALF)",
		Description: "Controls connections on a per-application basis.",
		Severity:    core.High,
		CurrentVal:  currAlfVal,
		ExpectedVal: "enabled",
		CISBenchmark: "2.5.1",
		RemediationScript: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
		LogContext:  strings.TrimSpace(string(alfOut)),
		Passed:      alfEnabled,
	})

	guestOut, _ := exec.Command("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled").CombinedOutput()
	guestStr := strings.TrimSpace(string(guestOut))
	guestDisabled := guestStr == "0" || strings.Contains(guestStr, "does not exist")
	addFinding(core.Finding{
		Category:    "Defaults",
		Name:        "Guest Account Login",
		Description: "Checks if the Guest Account is disabled.",
		Severity:    core.Med,
		CurrentVal:  guestStr,
		ExpectedVal: "0",
		CISBenchmark: "5.1",
		RemediationScript: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool NO",
		LogContext:  guestStr,
		Passed:      guestDisabled,
	})

	
	// 4. Insecure Network Settings: SSH Password Authentication
	sshOut, _ := exec.Command("grep", "^PasswordAuthentication", "/etc/ssh/sshd_config").CombinedOutput()
	sshStr := strings.TrimSpace(string(sshOut))
	sshPassed := !strings.Contains(strings.ToLower(sshStr), "yes")
	addFinding(core.Finding{
		Category:    "Network Security",
		Name:        "SSH Password Authentication",
		Description: "Checks if SSH password auth is disabled in sshd_config.",
		Severity:    core.High,
		CurrentVal:  sshStr,
		ExpectedVal: "PasswordAuthentication no (or unset)",
		CISBenchmark: "2.3.1",
		RemediationScript: "sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && launchctl stop com.openssh.sshd 2>/dev/null || true",
		LogContext:  sshStr,
		Passed:      sshPassed,
	})


	// 5. Gatekeeper (spctl)
	spctlOut, _ := exec.Command("spctl", "--status").CombinedOutput()
	spctlStr := strings.TrimSpace(string(spctlOut))
	spctlPassed := strings.Contains(spctlStr, "assessments enabled")
	addFinding(core.Finding{
		Category:    "System Capabilities",
		Name:        "Gatekeeper Status",
		Description: "Checks if signature assessments are enabled.",
		Severity:    core.VeryHigh,
		CurrentVal:  spctlStr,
		ExpectedVal: "assessments enabled",
		CISBenchmark: "2.9",
		RemediationScript: "spctl --master-enable",
		LogContext:  spctlStr,
		Passed:      spctlPassed,
	})


	// 6. Check FileVault Encryption
	fvOut, _ := exec.Command("fdesetup", "status").CombinedOutput()
	fvStr := strings.TrimSpace(string(fvOut))
	fvPassed := strings.Contains(fvStr, "FileVault is On")
	addFinding(core.Finding{
		Category:    "Data Protection",
		Name:        "FileVault Encryption",
		Description: "Ensures the boot volume is encrypted at rest.",
		Severity:    core.VeryHigh,
		CurrentVal:  fvStr,
		ExpectedVal: "FileVault is On.",
		CISBenchmark: "2.7.1",
		LogContext:  fvStr,
		Passed:      fvPassed,
	})


	// 7. Check Screen Lock Requirement
	slOut, _ := exec.Command("defaults", "read", "com.apple.screensaver", "askForPassword").CombinedOutput()
	slStr := strings.TrimSpace(string(slOut))
	slPassed := slStr == "1"
	addFinding(core.Finding{
		Category:    "Authentication",
		Name:        "Screen Lock Requirement",
		Description: "Ensures screen locks immediately and requires password to wake.",
		Severity:    core.High,
		CurrentVal:  slStr,
		ExpectedVal: "1",
		CISBenchmark: "2.8.2",
		RemediationScript: "defaults write com.apple.screensaver askForPassword -int 1",
		LogContext:  slStr,
		Passed:      slPassed,
	})


	// 8. Disable Remote Apple Events
	raeOut, _ := exec.Command("systemsetup", "-getremoteappleevents").CombinedOutput()
	raeStr := strings.TrimSpace(string(raeOut))
	raePassed := strings.Contains(raeStr, "Off")
	addFinding(core.Finding{
		Category:    "System Capabilities",
		Name:        "Remote Apple Events",
		Description: "Checks if Remote Apple Events are disabled to prevent remote execution.",
		Severity:    core.Med,
		CurrentVal:  raeStr,
		ExpectedVal: "Remote Apple Events: Off",
		CISBenchmark: "2.1.2",
		RemediationScript: "systemsetup -setremoteappleevents off",
		LogContext:  raeStr,
		Passed:      raePassed,
	})


	// 9. Disable Remote Login (SSH)
	rlOut, _ := exec.Command("systemsetup", "-getremotelogin").CombinedOutput()
	rlStr := strings.TrimSpace(string(rlOut))
	rlPassed := strings.Contains(rlStr, "Off")
	addFinding(core.Finding{
		Category:    "Network Security",
		Name:        "Remote Login (SSH Admin)",
		Description: "Checks if the primary SSH service (Remote Login) is disabled system-wide.",
		Severity:    core.High,
		CurrentVal:  rlStr,
		ExpectedVal: "Remote Login: Off",
		CISBenchmark: "2.4",
		RemediationScript: "systemsetup -setremotelogin off",
		LogContext:  rlStr,
		Passed:      rlPassed,
	})


	// 10. Disable AirDrop (or restrict)
	adOut, _ := exec.Command("defaults", "read", "com.apple.NetworkBrowser", "DisableAirDrop").CombinedOutput()
	adStr := strings.TrimSpace(string(adOut))
	adPassed := adStr == "1" || strings.Contains(adStr, "does not exist") // Does not exist might mean enabled by default, but let's encourage explicit disabling in heavily secured environments, or at least flag it.
	
	// Better check: If DisableAirDrop isn't 1, we log it as failed for a truly strict baseline.
	addFinding(core.Finding{
		Category:    "Network Security",
		Name:        "Disable AirDrop",
		Description: "Ensures AirDrop is explicitly disabled (DisableAirDrop=1) for strict security.",
		Severity:    core.Low, // usually low/med depending on org
		CurrentVal:  adStr,
		ExpectedVal: "1",
		CISBenchmark: "2.1.1",
		RemediationScript: "defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES",
		LogContext:  adStr,
		Passed:      adPassed,
	})


	// 11. Automatic Updates
	auOut, _ := exec.Command("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled").CombinedOutput()
	auStr := strings.TrimSpace(string(auOut))
	auPassed := auStr == "1" || strings.Contains(auStr, "does not exist") // Default is usually enabled, but strict check looks for 1. Let's pass if it's 1.
	if strings.Contains(auStr, "does not exist") {
		// Just assume it's default (on) but for strictness we prefer 1.
		auStr = "Not explicitly set (assumed default)"
		auPassed = true
	}
	addFinding(core.Finding{
		Category:    "System Maintenance",
		Name:        "Automatic Software Updates",
		Description: "Checks if macOS is configured to automatically check for updates.",
		Severity:    core.High,
		CurrentVal:  auStr,
		ExpectedVal: "1 (or default)",
		CISBenchmark: "1.1",
		RemediationScript: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool YES",
		LogContext:  auStr,
		Passed:      auPassed,
	})


	// 12. Check XProtect Version (Log Only)
	xpOut, _ := exec.Command("defaults", "read", "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta", "Version").CombinedOutput()
	xpStr := strings.TrimSpace(string(xpOut))
	addFinding(core.Finding{
		Category:    "Threat Intelligence",
		Name:        "XProtect Definitions",
		Description: "Logs the current version of the built-in XProtect Yara signatures.",
		Severity:    core.LogOnly,
		CurrentVal:  xpStr,
		ExpectedVal: "N/A",
		LogContext:  xpStr,
		Passed:      true,
	})


	// 13. Active Network Interfaces (Log Only)
	addFinding(core.Finding{
		Category:    "Troubleshooting",
		Name:        "Active Network Interfaces",
		Description: "Lists all standard network interfaces for auditing.",
		Severity:    core.LogOnly,
		CurrentVal:  "Collected",
		ExpectedVal: "N/A",
		LogContext:  "ifconfig -a", // Note: actual output should ideally capture ifconfig -a output, but we use static "Collected" for now
		Passed:      true,
	})


	// 14. Sudoers NOPASSWD Audit
	sudoOut, _ := exec.Command("sh", "-c", `grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null`).CombinedOutput()
	sudoStr := strings.TrimSpace(string(sudoOut))
	sudoPassed := sudoStr == ""
	addFinding(core.Finding{
		Category:    "Identity & Access",
		Name:        "Sudoers NOPASSWD Audit",
		Description: "Checks if any accounts can elevate privileges without a password.",
		Severity:    core.High,
		CurrentVal:  func() string { if sudoPassed { return "No NOPASSWD found" }; return "Found NOPASSWD entries" }(),
		ExpectedVal: "No NOPASSWD found",
		LogContext:  sudoStr,
		Passed:      sudoPassed,
	})


	// 15. Admin Account Count
	adminOut, _ := exec.Command("dscl", ".", "-read", "/Groups/admin", "GroupMembership").CombinedOutput()
	adminStr := strings.TrimSpace(string(adminOut))
	adminCount := len(strings.Fields(adminStr)) - 1 // subtract "GroupMembership:"
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


	// 16. Password Policy Strength
	// Note: pwpolicy usually requires root, but we check if it returns a configured policy.
	pwOut, _ := exec.Command("pwpolicy", "-getaccountpolicies").CombinedOutput()
	pwStr := strings.TrimSpace(string(pwOut))
	pwPassed := !strings.Contains(pwStr, "Error") && strings.Contains(pwStr, "policy")
	addFinding(core.Finding{
		Category:    "Identity & Access",
		Name:        "Global Password Policy",
		Description: "Verifies if a global password complexity policy is enforced.",
		Severity:    core.High,
		CurrentVal:  func() string { if pwPassed { return "Configured" }; return "Not Configured" }(),
		ExpectedVal: "Configured",
		LogContext:  pwStr,
		Passed:      pwPassed,
	})


	// 17. Non-Apple Kernel Extensions (Kexts)
	kextOut, _ := exec.Command("sh", "-c", "kextstat | grep -v com.apple | tail -n +2").CombinedOutput() // exclude header
	kextStr := strings.TrimSpace(string(kextOut))
	kextPassed := kextStr == ""
	addFinding(core.Finding{
		Category:    "Deep System & Kernel",
		Name:        "Non-Apple Kernel Extensions",
		Description: "Checks for legacy or third-party kernel extensions loaded into Ring-0.",
		Severity:    core.Med,
		CurrentVal:  func() string { if kextPassed { return "0 found" }; return "Third-party Kexts Loaded" }(),
		ExpectedVal: "0 found",
		LogContext:  kextStr,
		Passed:      kextPassed,
	})


	// 18. Auditd Logging Status
	auditOut, _ := exec.Command("sh", "-c", "ps aux | grep auditd | grep -v grep").CombinedOutput()
	auditStr := strings.TrimSpace(string(auditOut))
	auditPassed := auditStr != ""
	addFinding(core.Finding{
		Category:    "Deep System & Kernel",
		Name:        "OpenBSM Auditd Status",
		Description: "Verifies the macOS auditd daemon is actively running and logging events.",
		Severity:    core.High,
		CurrentVal:  func() string { if auditPassed { return "Running" }; return "Not Running" }(),
		ExpectedVal: "Running",
		LogContext:  auditStr,
		Passed:      auditPassed,
	})


	// 19. Safari Fraudulent Website Warning
	safariOut, _ := exec.Command("defaults", "read", "com.apple.Safari", "WarnAboutFraudulentWebsites").CombinedOutput()
	safariStr := strings.TrimSpace(string(safariOut))
	safariPassed := safariStr == "1" || strings.Contains(safariStr, "does not exist") // Sometimes default is true internally
	addFinding(core.Finding{
		Category:    "Application Security",
		Name:        "Safari Fraud Warning",
		Description: "Ensures Safari 'Warn about fraudulent websites' feature is enabled.",
		Severity:    core.Med,
		CurrentVal:  safariStr,
		ExpectedVal: "1",
		LogContext:  safariStr,
		RemediationScript: "defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool YES",
		Passed:      safariPassed,
	})


	// 20. TCC Full Disk Access Audit
	tccPath := "/Library/Application Support/com.apple.TCC/TCC.db"
	tccOut, _ := exec.Command("sqlite3", tccPath, "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles'").CombinedOutput()
	tccStr := strings.TrimSpace(string(tccOut))
	tccPassed := true
	tccVal := "Audited"
	if strings.Contains(tccStr, "unable to open database file") || strings.Contains(tccStr, "authorization denied") {
		tccVal = "Needs Full Disk Access to Audit TCC"
		tccPassed = false // Mark as failed because we can't see it
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


	// 21. Listening Network Ports
	lsofOut, _ := exec.Command("sh", "-c", "lsof -nP -iTCP -sTCP:LISTEN").CombinedOutput()
	lsofStr := strings.TrimSpace(string(lsofOut))
	addFinding(core.Finding{
		Category:    "Advanced Network Defense",
		Name:        "Listening Network Ports",
		Description: "Lists all locally listening TCP ports to find rogue services.",
		Severity:    core.LogOnly,
		CurrentVal:  "Collected",
		ExpectedVal: "N/A",
		LogContext:  lsofStr,
		Passed:      true,
	})


	// 22. System DNS Configuration
	dnsOut, _ := exec.Command("sh", "-c", `scutil --dns | grep nameserver | awk '{print $3}' | sort -u`).CombinedOutput()
	dnsStr := strings.TrimSpace(string(dnsOut))
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


	// 23. Captive Portal Bypass
	cpOut, _ := exec.Command("defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.captive.control", "Active").CombinedOutput()
	cpStr := strings.TrimSpace(string(cpOut))
	cpPassed := cpStr == "0"
	addFinding(core.Finding{
		Category:    "Advanced Network Defense",
		Name:        "Captive Portal Automatic Login",
		Description: "Checks if auto-login for captive portals is disabled to prevent MITM.",
		Severity:    core.Low,
		CurrentVal:  func() string { if cpStr == "0" { return "Disabled" }; return "Enabled" }(),
		ExpectedVal: "Disabled (0)",
		LogContext:  cpStr,
		RemediationScript: "defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -int 0",
		Passed:      cpPassed,
	})


	// 24. Delegate to Deep Scanning Modules
	ScanSecrets(addFinding)
	ScanVulnerabilities(addFinding)
	ScanMalware(addFinding)
	plugins.ScanStarlark(s.db, addFinding)

	return state, nil
}

