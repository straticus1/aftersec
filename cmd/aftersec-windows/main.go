// aftersec-windows provides read-only Windows posture checks.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

type commandRunner func(context.Context, string) ([]byte, error)

func scan(ctx context.Context, run commandRunner) []check {
	checks := []struct{ name, script string }{
		{"Defender real-time protection", "$s = Get-MpComputerStatus -ErrorAction Stop; [bool]($s.AntivirusEnabled -and $s.RealTimeProtectionEnabled) | ConvertTo-Json -Compress"},
		{"Windows Firewall profiles", "$p = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop); [bool]($p.Count -ge 3 -and @($p | Where-Object { $_.Enabled -ne $true }).Count -eq 0) | ConvertTo-Json -Compress"},
	}
	results := make([]check, 0, len(checks))
	for _, c := range checks {
		result := check{Name: c.name}
		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		output, err := run(checkCtx, "$ErrorActionPreference = 'Stop'; "+c.script)
		if checkCtx.Err() != nil {
			err = checkCtx.Err()
		}
		cancel()
		if err != nil {
			result.Error = err.Error()
		} else {
			var passed *bool
			if err := json.Unmarshal(output, &passed); err != nil || passed == nil {
				result.Error = "invalid PowerShell result"
			} else {
				result.Passed = *passed
			}
		}
		results = append(results, result)
	}
	return results
}

// limitWriter bounds command output even if the child produces unexpected data.
type limitWriter struct{ data []byte }

func (w *limitWriter) Write(p []byte) (int, error) {
	if len(w.data)+len(p) > 64*1024 {
		return 0, fmt.Errorf("command output exceeds 64 KiB")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("SystemRoot must be an absolute path")
	}
	command := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, command, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	var output limitWriter
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return output.data, err
}

func main() {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "This scanner requires Windows.")
		os.Exit(2)
	}
	if len(os.Args) != 1 && (len(os.Args) != 2 || os.Args[1] != "scan") {
		fmt.Fprintln(os.Stderr, "Usage: aftersec-windows [scan]")
		os.Exit(2)
	}
	results := scan(context.Background(), runPowerShell)
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, result := range results {
		if !result.Passed {
			os.Exit(1)
		}
	}
}
