package scanners

import (
	"aftersec/pkg/core"
	"os/exec"
	"strings"
)

func ScanVulnerabilities(addFinding func(core.Finding)) {
	// 1. Brew Outdated / Vulnerable check
	// We'll run a fast command. Full 'brew audit' is too slow for GUI sync.
	// Let's just check if brew requires updates or formulas are outdated.
	brewOut, _ := exec.Command("brew", "outdated").CombinedOutput()
	brewStr := strings.TrimSpace(string(brewOut))
	
	lines := strings.Split(brewStr, "\n")
	passed := len(brewStr) == 0
	val := "Up to date"
	if !passed {
		val = "Outdated packages found"
		if len(lines) > 5 {
			val = "5+ outdated packages found"
		}
	}

	addFinding(core.Finding{
		Category:     "Vulnerability Management",
		Name:         "Homebrew Packages Outdated",
		Description:  "Checks if installed Homebrew packages are severely outdated.",
		Severity:     core.Low,
		CurrentVal:   val,
		ExpectedVal:  "Up to date",
		CISBenchmark: "",
		LogContext:   brewStr,
		Passed:       passed,
	})
}
