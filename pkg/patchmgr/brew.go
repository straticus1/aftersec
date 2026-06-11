//go:build darwin

package patchmgr

import (
	"encoding/json"
	"os/exec"
)

type BrewManager struct {
	run func() ([]byte, error)
}

func NewBrewManager() *BrewManager {
	return &BrewManager{
		run: func() ([]byte, error) {
			return exec.Command("brew", "outdated", "--json=v2").CombinedOutput()
		},
	}
}

func (b *BrewManager) Name() string { return "brew" }

func (b *BrewManager) RemediateCmd(pkg OutdatedPackage) string {
	return "brew upgrade " + pkg.Name
}

func (b *BrewManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := b.run()
	if err != nil {
		return nil, err
	}
	return parseBrewJSON(data)
}

type brewJSON struct {
	Formulae []struct {
		Name              string   `json:"name"`
		InstalledVersions []string `json:"installed_versions"`
		CurrentVersion    string   `json:"current_version"`
	} `json:"formulae"`
}

func parseBrewJSON(data []byte) ([]OutdatedPackage, error) {
	var b brewJSON
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	pkgs := make([]OutdatedPackage, 0, len(b.Formulae))
	for _, f := range b.Formulae {
		installed := ""
		if len(f.InstalledVersions) > 0 {
			installed = f.InstalledVersions[0]
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:    f.Name,
				Version: installed,
				Source:  "brew",
			},
			LatestVersion: f.CurrentVersion,
		})
	}
	return pkgs, nil
}
