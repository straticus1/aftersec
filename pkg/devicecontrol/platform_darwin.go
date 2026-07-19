//go:build darwin

package devicecontrol

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DarwinMounter applies removable-media decisions through Disk Arbitration's
// diskutil control surface. The daemon must run with the entitlement/privilege
// required by the host; command failure is returned and never treated as allow.
// Threats: unauthorized removable-media mounts and write access. It does not
// replace an Endpoint Security or Network Extension system extension.
type DarwinMounter struct{}

func NewPlatformMounter() Mounter { return DarwinMounter{} }

func (DarwinMounter) Apply(device Device, access Access) error {
	if !strings.HasPrefix(string(device.ID), "/dev/disk") {
		return fmt.Errorf("invalid Darwin disk identity")
	}
	var args []string
	switch access {
	case Deny:
		args = []string{"unmountDisk", "force", string(device.ID)}
	case ReadOnly:
		args = []string{"mount", "readOnly", string(device.ID)}
	case ReadWrite:
		args = []string{"mount", string(device.ID)}
	default:
		return ErrDeviceDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/sbin/diskutil", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("disk arbitration decision failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
