package plugins

import (
	"aftersec/pkg/client/storage"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func getRulesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/aftersec/rules"
	}
	return filepath.Join(home, ".aftersec", "rules")
}

// NumYaraRules returns the number of custom YARA rules configured by the user.
func NumYaraRules() int {
	files, err := os.ReadDir(getRulesDir())
	if err != nil {
		return 0
	}
	count := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".yar") || strings.HasSuffix(f.Name(), ".yara") {
			count++
		}
	}
	return count
}

// ScanYara evaluates a specific target path against all active user YARA rules.
// Returns true if ANY rule matches (malicious).
func ScanYara(db storage.Manager, targetPath string) (bool, error) {
	return scanYara(db, targetPath, 5*time.Second)
}

func scanYara(db storage.Manager, targetPath string, timeout time.Duration) (bool, error) {
	rulesDir := getRulesDir()
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		// No custom rules directory exists
		return false, nil
	}

	files, err := os.ReadDir(rulesDir)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, f := range files {
		if f.IsDir() || (!strings.HasSuffix(f.Name(), ".yar") && !strings.HasSuffix(f.Name(), ".yara")) {
			continue
		}
		// The CLI accepts one rules file and one target per invocation.
		cmd := exec.CommandContext(ctx, "yara", filepath.Join(rulesDir, f.Name()), targetPath)
		var output, diagnostics yaraOutput
		cmd.Stdout, cmd.Stderr = &output, &diagnostics
		if err := cmd.Run(); err != nil {
			return false, fmt.Errorf("YARA rule %s: %w: %s", f.Name(), err, diagnostics.String())
		}
		if strings.TrimSpace(output.String()) != "" {
			msg := fmt.Sprintf("YARA match in %s for %s: %s", f.Name(), targetPath, output.String())
			if db != nil {
				if err := db.LogTelemetryEvent("yara_engine", "rule_match", "critical", msg); err != nil {
					return true, err
				}
			}
			log.Print(msg)
			return true, nil
		}
	}
	return false, nil
}

// Bound both stdout and stderr from the external rule engine.
type yaraOutput struct{ buffer bytes.Buffer }

func (b *yaraOutput) Write(p []byte) (int, error) {
	if len(p) > 64*1024-b.buffer.Len() {
		return 0, fmt.Errorf("YARA output exceeds limit")
	}
	return b.buffer.Write(p)
}

func (b *yaraOutput) String() string { return b.buffer.String() }
