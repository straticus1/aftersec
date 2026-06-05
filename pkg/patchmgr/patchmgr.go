package patchmgr

import (
	"aftersec/pkg/core"
	"fmt"
)

// PackageManager discovers outdated packages and generates remediation commands.
type PackageManager interface {
	Name() string
	ListOutdated() ([]OutdatedPackage, error)
	RemediateCmd(pkg OutdatedPackage) string
}

type InstalledPackage struct {
	Name    string
	Version string
	Source  string // "brew", "softwareupdate", "apt", "dnf", "pacman"
}

type OutdatedPackage struct {
	InstalledPackage
	LatestVersion string
	CVEs          []CVE
}

type CVE struct {
	ID          string
	Score       float64 // CVSS v3 base score; 0 if unknown
	Description string
}

// CVESeverity maps the highest CVE score in a package to a core.Severity.
func CVESeverity(cves []CVE) core.Severity {
	var max float64
	for _, c := range cves {
		if c.Score > max {
			max = c.Score
		}
	}
	switch {
	case max >= 9.0:
		return core.Critical
	case max >= 7.0:
		return core.High
	case max >= 4.0:
		return core.Med
	default:
		return core.Low
	}
}

// FormatCVEs returns a compact string listing CVE IDs and scores.
func FormatCVEs(cves []CVE) string {
	if len(cves) == 0 {
		return ""
	}
	out := ""
	for i, c := range cves {
		if i > 0 {
			out += ", "
		}
		if c.Score > 0 {
			out += fmt.Sprintf("%s (%.1f)", c.ID, c.Score)
		} else {
			out += c.ID
		}
	}
	return out
}
