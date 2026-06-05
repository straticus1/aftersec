//go:build linux

package patchmgr

import (
	"os/exec"
	"regexp"
	"strings"
)

type AptManager struct {
	run func() ([]byte, error)
}

func NewAptManager() *AptManager {
	return &AptManager{
		run: func() ([]byte, error) {
			return exec.Command("apt", "list", "--upgradable").CombinedOutput()
		},
	}
}

func (a *AptManager) Name() string { return "apt" }

func (a *AptManager) RemediateCmd(pkg OutdatedPackage) string {
	return "apt-get install --only-upgrade -y " + pkg.Name
}

func (a *AptManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := a.run()
	if err != nil {
		return nil, err
	}
	return parseAptOutput(string(data)), nil
}

// aptLineRe matches: curl/focal-security 7.68.0-1 amd64 [upgradable from: 7.68.0-0]
var aptLineRe = regexp.MustCompile(`^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]`)

func parseAptOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	for _, line := range strings.Split(output, "\n") {
		m := aptLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:    m[1],
				Version: m[3],
				Source:  "apt",
			},
			LatestVersion: m[2],
		})
	}
	return pkgs
}
