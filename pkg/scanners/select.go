package scanners

import "fmt"

// ValidateProfile rejects a scan profile the engine does not implement.
func ValidateProfile(profile string) error {
	switch profile {
	case "", "quick", "standard", "thorough", "custom":
		return nil
	default:
		return fmt.Errorf("unknown scan profile %q", profile)
	}
}

// KnownCategory reports whether a --category flag selects a real group.
func KnownCategory(category string) bool {
	switch category {
	case "", "all", "system", "network", "filesystem":
		return true
	default:
		return false
	}
}

// MatchCategory reports whether a finding belongs to the requested group.
// An empty or all selector includes every finding.
func MatchCategory(group, findingCategory string) bool {
	if group == "" || group == "all" {
		return true
	}
	switch group {
	case "system":
		switch findingCategory {
		case "System Capabilities", "System Maintenance", "Defaults", "Deep System & Kernel", "Application Security", "Scan Engine", "Patch Management":
			return true
		}
	case "network":
		switch findingCategory {
		case "Network Security", "Advanced Network Defense":
			return true
		}
	case "filesystem":
		switch findingCategory {
		case "Source Scan", "Binary Trace", "Developer Secrets Hygiene", "Agentic Endpoint", "File Integrity":
			return true
		}
	}
	return false
}
