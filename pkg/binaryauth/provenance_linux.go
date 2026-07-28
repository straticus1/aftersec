//go:build linux

package binaryauth

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func platformProvenance(path string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		output, queryErr := exec.CommandContext(ctx, "dpkg-query", "-S", path).Output()
		if queryErr == nil {
			pkg := strings.TrimSpace(strings.SplitN(string(output), ":", 2)[0])
			if pkg != "" {
				return "", "deb:" + pkg, nil
			}
		}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		output, queryErr := exec.CommandContext(ctx, "rpm", "-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}", path).Output()
		if queryErr == nil && strings.TrimSpace(string(output)) != "" {
			return "", "rpm:" + strings.TrimSpace(string(output)), nil
		}
	}
	// A locally built executable is a valid identity, but has no trusted package
	// provenance. The signed hash policy still decides whether it may execute.
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("package provenance lookup: %w", ctx.Err())
	}
	return "", "", nil
}
