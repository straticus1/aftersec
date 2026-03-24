package forensics

import "strings"

type ThreatScore int

const (
	Safe ThreatScore = iota
	Suspicious
	Malicious
)

func (t ThreatScore) String() string {
	switch t {
	case Safe:
		return "SAFE"
	case Suspicious:
		return "SUSPICIOUS"
	case Malicious:
		return "MALICIOUS"
	default:
		return "UNKNOWN"
	}
}

type ProcessFinding struct {
	PID         int
	Command     string
	User        string
	Score       ThreatScore
	Reason      string
	KillCommand string
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// CheckSignature evaluates a command execution against known threat intelligence heuristics.
func CheckSignature(cmd string) (ThreatScore, string) {
	// 1. Cryptocurrency Miners
	if containsAny(cmd, "xmrig", "minergate", "cgminer", "stratum+tcp://") {
		return Malicious, "Known cryptocurrency mining signature detected in memory."
	}
	
	// 2. Pivot & Reverse Shells
	if containsAny(cmd, "nc -e", "bash -i", "/dev/tcp/", "sh -i", "ncat -e") {
		return Malicious, "Suspicious reverse shell or netcat pivot listener detected."
	}
	
	// 3. Info Stealers & Exfiltration
	if containsAny(cmd, "curl -d @", "wget --post-file", "scp -r /Users") {
		return Suspicious, "Potential data exfiltration mechanism detected."
	}
	
	// 4. Recon & Post-Exploitation
	if containsAny(cmd, "nmap", "masscan", "bloodhound") {
		return Suspicious, "Active network scanning or Active Directory recon utility."
	}
	
	// 5. System Modification
	if containsAny(cmd, "chmod 777 /etc", "chown root:wheel /tmp") {
		return Malicious, "Dangerous system privilege escalation or persistence execution."
	}

	return Safe, ""
}
