//go:build linux

package patchmgr

import (
	"os/exec"
	"strings"
)

type DnfManager struct {
	run func() ([]byte, error)
}

func NewDnfManager() *DnfManager {
	return &DnfManager{
		run: func() ([]byte, error) {
			return exec.Command("dnf", "check-update", "--quiet").CombinedOutput()
		},
	}
}

func (d *DnfManager) Name() string { return "dnf" }

func (d *DnfManager) RemediateCmd(pkg OutdatedPackage) string {
	return "dnf upgrade -y " + pkg.Name
}

func (d *DnfManager) ListOutdated() ([]OutdatedPackage, error) {
	data, _ := d.run() // dnf check-update exits 100 when updates exist; ignore error
	return parseDnfOutput(string(data)), nil
}

// parseDnfOutput parses "dnf check-update" output: "curl.x86_64    7.76.1-31.el9    baseos"
func parseDnfOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if strings.HasPrefix(name, "Last") || strings.HasPrefix(name, "Obsoleting") {
			continue
		}
		// Strip arch suffix: curl.x86_64 → curl
		if idx := strings.LastIndex(name, "."); idx > 0 {
			name = name[:idx]
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:   name,
				Source: "dnf",
			},
			LatestVersion: fields[1],
		})
	}
	return pkgs
}
