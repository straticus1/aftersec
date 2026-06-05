//go:build linux

package patchmgr

import (
	"os/exec"
	"strings"
)

type PacmanManager struct {
	run func() ([]byte, error)
}

func NewPacmanManager() *PacmanManager {
	return &PacmanManager{
		run: func() ([]byte, error) {
			return exec.Command("pacman", "-Qu").CombinedOutput()
		},
	}
}

func (p *PacmanManager) Name() string { return "pacman" }

func (p *PacmanManager) RemediateCmd(pkg OutdatedPackage) string {
	return "pacman -S --noconfirm " + pkg.Name
}

func (p *PacmanManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := p.run()
	if err != nil {
		return nil, err
	}
	return parsePacmanOutput(string(data)), nil
}

// parsePacmanOutput parses "pacman -Qu" output: "curl 8.1.2-1 -> 8.6.0-1"
func parsePacmanOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:    fields[0],
				Version: fields[1],
				Source:  "pacman",
			},
			LatestVersion: fields[3],
		})
	}
	return pkgs
}
