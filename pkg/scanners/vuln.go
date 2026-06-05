package scanners

import (
	"aftersec/pkg/core"
	"aftersec/pkg/patchmgr"
	"fmt"
)

func ScanVulnerabilities(addFinding func(core.Finding)) {
	for _, mgr := range patchmgr.ForPlatform() {
		outdated, err := mgr.ListOutdated()
		if err != nil {
			addFinding(core.Finding{
				Category:    "Patch Management",
				Name:        fmt.Sprintf("%s: scan failed", mgr.Name()),
				Description: "Could not retrieve package list.",
				Severity:    core.Low,
				CurrentVal:  err.Error(),
				ExpectedVal: "no error",
				Passed:      false,
			})
			continue
		}

		patchmgr.EnrichWithCVEs(outdated)

		var noCVEOutdated []patchmgr.OutdatedPackage
		for _, pkg := range outdated {
			if len(pkg.CVEs) == 0 {
				noCVEOutdated = append(noCVEOutdated, pkg)
				continue
			}
			addFinding(core.Finding{
				Category:          "Patch Management",
				Name:              fmt.Sprintf("[%s] %s outdated", mgr.Name(), pkg.Name),
				Description:       fmt.Sprintf("Installed: %s, Latest: %s", pkg.Version, pkg.LatestVersion),
				Severity:          patchmgr.CVESeverity(pkg.CVEs),
				CurrentVal:        pkg.Version,
				ExpectedVal:       pkg.LatestVersion,
				LogContext:        patchmgr.FormatCVEs(pkg.CVEs),
				Passed:            false,
				RemediationScript: mgr.RemediateCmd(pkg),
			})
		}

		// Rolled-up finding for outdated packages without known CVEs
		if len(noCVEOutdated) > 0 {
			addFinding(core.Finding{
				Category:    "Patch Management",
				Name:        fmt.Sprintf("[%s] %d outdated package(s), no known CVEs", mgr.Name(), len(noCVEOutdated)),
				Severity:    core.Low,
				CurrentVal:  fmt.Sprintf("%d outdated", len(noCVEOutdated)),
				ExpectedVal: "0 outdated",
				Passed:      false,
			})
		}

		if len(outdated) == 0 {
			addFinding(core.Finding{
				Category:    "Patch Management",
				Name:        fmt.Sprintf("[%s] all packages up to date", mgr.Name()),
				Severity:    core.Low,
				CurrentVal:  "up to date",
				ExpectedVal: "up to date",
				Passed:      true,
			})
		}
	}
}
