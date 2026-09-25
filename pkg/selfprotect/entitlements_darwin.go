//go:build darwin

package selfprotect

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func platformEntitlements() []string {
	return []string{"com.apple.developer.endpoint-security.client"}
}

func readEntitlementKeys(ctx context.Context, executable string) ([]string, error) {
	if executable == "" {
		return nil, fmt.Errorf("agent executable path is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "codesign", "-d", "--entitlements", ":-", executable)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read code signature entitlements: %w", err)
	}
	return ParseEntitlementKeys(out)
}
