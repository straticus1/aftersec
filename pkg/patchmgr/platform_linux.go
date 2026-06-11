//go:build linux

package patchmgr

import "os/exec"

// ForPlatform returns all available package managers on Linux.
func ForPlatform() []PackageManager {
	var mgrs []PackageManager
	if _, err := exec.LookPath("apt"); err == nil {
		mgrs = append(mgrs, NewAptManager())
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		mgrs = append(mgrs, NewDnfManager())
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		mgrs = append(mgrs, NewPacmanManager())
	}
	return mgrs
}
