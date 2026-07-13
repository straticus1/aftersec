//go:build linux

package response

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

type NFTFirewall struct{ table string }

func NewPlatformFirewall() Firewall { return &NFTFirewall{table: "aftersec_quarantine"} }
func (f *NFTFirewall) Apply(ctx context.Context, e ControlEndpoint) error {
	script := fmt.Sprintf("add table inet %s\nadd chain inet %s output { type filter hook output priority -300; policy drop; }\nadd rule inet %s output ip daddr %s tcp dport %d accept\n", f.table, f.table, f.table, e.Host, e.Port)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply: %w: %s", err, string(out))
	}
	return nil
}
func (f *NFTFirewall) VerifyControl(ctx context.Context, _ ControlEndpoint) error {
	if out, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", f.table).CombinedOutput(); err != nil {
		return fmt.Errorf("nft verify: %w: %s", err, string(out))
	}
	return nil
}
func (f *NFTFirewall) Remove(ctx context.Context) error {
	if out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", f.table).CombinedOutput(); err != nil {
		return fmt.Errorf("nft remove: %w: %s", err, string(out))
	}
	return nil
}
