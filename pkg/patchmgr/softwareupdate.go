//go:build darwin

package patchmgr

import (
	"os/exec"
	"regexp"
	"strings"
)

type SoftwareUpdateManager struct {
	run func() ([]byte, error)
}

func NewSoftwareUpdateManager() *SoftwareUpdateManager {
	return &SoftwareUpdateManager{
		run: func() ([]byte, error) {
			return exec.Command("softwareupdate", "-l").CombinedOutput()
		},
	}
}

func (s *SoftwareUpdateManager) Name() string { return "softwareupdate" }

func (s *SoftwareUpdateManager) RemediateCmd(pkg OutdatedPackage) string {
	return "softwareupdate --install " + pkg.Name
}

func (s *SoftwareUpdateManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := s.run()
	if err != nil {
		return nil, err
	}
	return parseSoftwareUpdateOutput(string(data)), nil
}

// labelRe matches lines like: * Label: Safari-17.4.1
var labelRe = regexp.MustCompile(`\*\s+Label:\s+(.+)`)

// titleVersionRe matches lines like:	Title: Safari, Version: 17.4.1, ...
var titleVersionRe = regexp.MustCompile(`Title:\s+([^,]+),\s+Version:\s+([^,]+)`)

func parseSoftwareUpdateOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	lines := strings.Split(output, "\n")
	var label string
	for _, line := range lines {
		if m := labelRe.FindStringSubmatch(line); m != nil {
			label = strings.TrimSpace(m[1])
			continue
		}
		if label != "" {
			if m := titleVersionRe.FindStringSubmatch(line); m != nil {
				pkgs = append(pkgs, OutdatedPackage{
					InstalledPackage: InstalledPackage{
						Name:   label,
						Source: "softwareupdate",
					},
					LatestVersion: strings.TrimSpace(m[2]),
				})
				label = ""
			}
		}
	}
	return pkgs
}
