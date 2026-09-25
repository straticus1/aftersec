package bintrace

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// lookupSignature is replaced in tests. The default never treats a failed
// lookup as signed.
var lookupSignature = defaultSignature

func defaultSignature(path string) (state, team string) {
	if _, err := exec.LookPath("codesign"); err == nil {
		return readCodesign(path)
	}
	if trustedPath(path) {
		return "distro", ""
	}
	return "unknown", ""
}

func readCodesign(path string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "codesign", "-dv", "--verbose=2", path).CombinedOutput()
	text := string(out)
	switch {
	case strings.Contains(text, "not signed"):
		return "unsigned", ""
	case strings.Contains(text, "Signature=adhoc"):
		return "adhoc", ""
	}
	team := field(text, "TeamIdentifier=")
	if team == "not set" {
		team = ""
	}
	if strings.Contains(text, "Authority=") || team != "" {
		return "signed", team
	}
	return "unknown", ""
}

func field(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, key); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
