//go:build linux

package devicecontrol

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// LinuxMounter delegates to udisksctl, whose polkit rules must enforce the
// daemon identity. Any helper failure is surfaced as denial.
// Threats: unauthorized removable-media mounts and write access; it does not
// replace a kernel USB authorization policy.
type LinuxMounter struct{}

func NewPlatformMounter() Mounter { return LinuxMounter{} }

func (LinuxMounter) Apply(device Device, access Access) error {
	if !strings.HasPrefix(string(device.ID), "/dev/") {
		return fmt.Errorf("invalid Linux device identity")
	}
	args := []string{"mount", "-b", string(device.ID)}
	if access == Deny {
		args = []string{"unmount", "-b", string(device.ID)}
	}
	if access == ReadOnly {
		args = append(args, "--options", "ro")
	}
	if access != Deny && access != ReadOnly && access != ReadWrite {
		return ErrDeviceDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/udisksctl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("udisks authorization failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
