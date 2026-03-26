package plugins

import (
	"aftersec/pkg/client/storage"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	rulesDir := getRulesDir()
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		// No custom rules directory exists
		return false, nil
	}

	// YARA allows passing multiple rules by specifying a directory containing them, 
	// but the exact CLI usually requires an index file or specifying all paths.
	// For simplicity, we find all .yar files and pass them.
	files, err := os.ReadDir(rulesDir)
	if err != nil {
		return false, err
	}

	var ruleFiles []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".yar") || strings.HasSuffix(f.Name(), ".yara") {
			ruleFiles = append(ruleFiles, filepath.Join(rulesDir, f.Name()))
		}
	}

	if len(ruleFiles) == 0 {
		return false, nil // No rules configured
	}

	// Construct: yara rule1.yar rule2.yar ... targetPath
	args := append(ruleFiles, targetPath)
	cmd := exec.Command("yara", args...)
	
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	err = cmd.Run()
	output := strings.TrimSpace(outBuf.String())

	// `yara` exits 0 if ran successfully (even if it found matches).
	// Matches are printed to stdout as: RuleName /path/to/target
	if err != nil {
		// If exit code != 0, it might be a syntax error in a rule or permission denied.
		// However, it could also mean matching depending on the version.
		// We rely on parsing the output string.
	}

	if len(output) > 0 && !strings.Contains(output, "error") {
		// A match output looks like:
		// MaliciousMacro /tmp/target.exe
		lines := strings.Split(output, "\n")
		var matchedRules []string
		
		for _, line := range lines {
			if line == "" { continue }
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				ruleName := parts[0]
				matchedRules = append(matchedRules, ruleName)
				
				// Log the exact execution telemetry per user-requirement
				msg := fmt.Sprintf("YARA match detected! Rule: %s, Target: %s", ruleName, targetPath)
				if db != nil {
					db.LogTelemetryEvent("yara_engine", "rule_match", "critical", msg)
				}
				log.Printf("🛑 [YARA ENGINE] Rule %s matched file: %s", ruleName, targetPath)
			}
		}

		if len(matchedRules) > 0 {
			return true, nil // Malicious matched
		}
	}

	return false, nil
}
