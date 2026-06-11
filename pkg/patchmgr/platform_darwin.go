//go:build darwin

package patchmgr

import "os/exec"

// ForPlatform returns all available package managers on macOS.
func ForPlatform() []PackageManager {
	var mgrs []PackageManager
	if _, err := exec.LookPath("brew"); err == nil {
		mgrs = append(mgrs, NewBrewManager())
	}
	mgrs = append(mgrs, NewSoftwareUpdateManager())
	return mgrs
}
