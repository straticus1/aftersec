package core

import "time"

type Severity string

const (
	LogOnly  Severity = "log-only"
	Low      Severity = "low"
	Med      Severity = "med"
	High     Severity = "high"
	VeryHigh Severity = "very-high"
)

type Finding struct {
	Category         string   `json:"category"` // e.g., "Network", "Defaults"
	Name             string   `json:"name"`     // e.g., "SSH Password Auth"
	Description      string   `json:"description"`
	Severity         Severity `json:"severity"`
	CurrentVal       string   `json:"current_val"`
	ExpectedVal      string   `json:"expected_val"`
	LogContext       string   `json:"log_context"` // Used for troubleshooting
	CISBenchmark     string   `json:"cis_benchmark,omitempty"` // e.g., "CIS 2.12"
	RemediationScript string  `json:"remediation_script,omitempty"` // Bash command to fix
	Passed           bool     `json:"passed"`
}

// SecurityState represents a snapshot of the macOS security posture.
type SecurityState struct {
	Timestamp time.Time `json:"timestamp"`
	Findings  []Finding `json:"findings"`
}
