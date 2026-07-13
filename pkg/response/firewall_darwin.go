//go:build darwin

package response

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

type PFFirewall struct{ anchor string }

func NewPlatformFirewall() Firewall { return &PFFirewall{anchor: "com.aftersec.quarantine"} }
func (f *PFFirewall) Apply(ctx context.Context, e ControlEndpoint) error {
	rules := fmt.Sprintf("block drop all\npass quick proto tcp to %s port %d keep state\n", e.Host, e.Port)
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", "-a", f.anchor, "-f", "-")
	cmd.Stdin = bytes.NewBufferString(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl apply: %w: %s", err, string(out))
	}
	return nil
}
func (f *PFFirewall) VerifyControl(ctx context.Context, e ControlEndpoint) error {
	out, err := exec.CommandContext(ctx, "/sbin/pfctl", "-a", f.anchor, "-sr").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl verify: %w", err)
	}
	needle := []byte("port = " + strconv.Itoa(int(e.Port)))
	if !bytes.Contains(out, needle) && !bytes.Contains(out, []byte("port "+strconv.Itoa(int(e.Port)))) {
		return fmt.Errorf("control allow rule absent")
	}
	return nil
}
func (f *PFFirewall) Remove(ctx context.Context) error {
	if out, err := exec.CommandContext(ctx, "/sbin/pfctl", "-a", f.anchor, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl remove: %w: %s", err, string(out))
	}
	return nil
}
