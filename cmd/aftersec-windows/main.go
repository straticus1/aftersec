// aftersec-windows provides read-only Windows posture checks.
//
// Threats: a spoofed SystemRoot, UNC path, user-writable PSModulePath, or
// planted PowerShell module can make this scanner attest healthy Defender or
// firewall. The runner pins the system Windows directory and system module
// path, disables module auto-loading, and fails closed on invalid JSON,
// timeouts, and oversized output. This does not WinVerifyTrust
// powershell.exe and does not inspect Defender path exclusions.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	maxCommandOutput = 64 * 1024
	checkTimeout     = 15 * time.Second
)

const powershellPreamble = "$PSModuleAutoLoadingPreference = 'None'; $ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; $OutputEncoding = [Console]::OutputEncoding; function Find-SystemModule([string[]]$names) { foreach ($root in @($env:PSModulePath -split [IO.Path]::PathSeparator)) { if (-not $root) { continue }; foreach ($name in $names) { $candidate = Join-Path $root $name; if (Test-Path -LiteralPath $candidate) { return $candidate } } }; throw ('module not found: ' + ($names -join ',')) }; "

const defenderScript = `$defender = Find-SystemModule @('Defender','ConfigDefender'); Import-Module -Name $defender -ErrorAction Stop; $s = Get-MpComputerStatus -ErrorAction Stop; [bool]($s.AntivirusEnabled -and $s.RealTimeProtectionEnabled) | ConvertTo-Json -Compress`

const firewallScript = `$net = Find-SystemModule @('NetSecurity'); Import-Module -Name $net -ErrorAction Stop; $p = @(Get-NetFirewallProfile -Name Domain,Private,Public -PolicyStore ActiveStore -ErrorAction Stop); if ($p.Count -ne 3) { throw 'incomplete firewall profiles' }; $names = @($p | ForEach-Object { $_.Name } | Sort-Object); if (($names -join ',') -ne 'Domain,Private,Public') { throw 'invalid firewall profile names' }; [bool](@($p | Where-Object { $_.Enabled -ne $true }).Count -eq 0) | ConvertTo-Json -Compress`

type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

type commandRunner func(context.Context, string) ([]byte, error)

func scan(ctx context.Context, run commandRunner) []check {
	checks := []struct{ name, script string }{
		{"Defender real-time protection", defenderScript},
		{"Windows Firewall profiles", firewallScript},
	}
	results := make([]check, 0, len(checks))
	for _, c := range checks {
		result := check{Name: c.name}
		checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
		output, err := run(checkCtx, powershellPreamble+c.script)
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
	if len(w.data)+len(p) > maxCommandOutput {
		w.data = nil
		return 0, fmt.Errorf("command output exceeds 64 KiB")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

func isUNC(path string) bool {
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//")
}

func validateAndCleanRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("SystemRoot must be an absolute path")
	}
	if isUNC(root) {
		return "", fmt.Errorf("SystemRoot must be a local drive path")
	}
	cleaned := filepath.Clean(root)
	if isUNC(cleaned) || !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("SystemRoot must be a local drive path")
	}
	if runtime.GOOS == "windows" && filepath.VolumeName(cleaned) == "" {
		return "", fmt.Errorf("SystemRoot must be a local drive path")
	}
	return cleaned, nil
}

func windowsRoot() (string, error) {
	if runtime.GOOS == "windows" {
		return systemWindowsRoot()
	}
	return validateAndCleanRoot(os.Getenv("SystemRoot"))
}

func overrideEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if ok && strings.EqualFold(k, key) {
			if !found {
				out = append(out, key+"="+value)
				found = true
			}
			continue
		}
		out = append(out, e)
	}
	if !found {
		out = append(out, key+"="+value)
	}
	return out
}

func powershellExe(root string) (string, error) {
	command := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	rel, err := filepath.Rel(root, command)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("powershell path escaped Windows directory")
	}
	return command, nil
}

func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	root, err := windowsRoot()
	if err != nil {
		return nil, err
	}
	command, err := powershellExe(root)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, command, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = overrideEnv(os.Environ(), "SystemRoot", root)
	cmd.Env = overrideEnv(cmd.Env, "WINDIR", root)
	cmd.Env = overrideEnv(cmd.Env, "PSModulePath", machineModulePath(root))
	var stdout, stderr limitWriter
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		if len(stderr.data) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(stderr.data)))
		}
		return nil, err
	}
	return stdout.data, nil
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "report" {
		runReport(os.Args[2:])
		return
	}
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
