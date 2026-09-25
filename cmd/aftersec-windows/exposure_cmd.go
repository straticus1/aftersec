package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"aftersec/pkg/exposure"
)

const diskScript = `$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; if ($v.ProtectionStatus -eq 'On') { 'true' } elseif ($v.ProtectionStatus -eq 'Off') { 'false' } else { throw 'bitlocker state is unrecognized' }`

const screenScript = `$deny = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name NoLockScreen -ErrorAction SilentlyContinue; if ($deny -and $deny.NoLockScreen -eq 1) { 'false'; return }; $sys = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction Stop; if ($sys.InactivityTimeoutSecs -gt 0) { 'true' } elseif ($sys.InactivityTimeoutSecs -eq 0) { 'false' } else { throw 'lock timeout is unrecognized' }`

const updateScript = `$au = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction Stop; if ($au.NoAutoUpdate -eq 1) { 'false' } elseif ($au.AUOptions -eq 4) { 'true' } else { throw 'update policy is unrecognized' }`

const remoteScript = `$ts = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop; if ($ts.fDenyTSConnections -eq 1) { 'true' } elseif ($ts.fDenyTSConnections -eq 0) { 'false' } else { throw 'remote desktop state is unrecognized' }`

func windowsExposureScript(name string) (string, bool) {
	switch name {
	case "windows-firewall":
		return firewallScript, true
	case "windows-disk":
		return diskScript, true
	case "windows-screen":
		return screenScript, true
	case "windows-update":
		return updateScript, true
	case "windows-remote":
		return remoteScript, true
	default:
		return "", false
	}
}

func runExposure() {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "This scanner requires Windows.")
		os.Exit(2)
	}
	report := exposure.Collect("windows", func(name string, _ ...string) (string, bool) {
		script, ok := windowsExposureScript(name)
		if !ok {
			return "", false
		}
		output, err := runPowerShell(context.Background(), powershellPreamble+script)
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(output)), true
	})
	body, err := exposure.Marshal(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "exposure report rejected")
		os.Exit(2)
	}
	fmt.Println(string(body))
	switch report.Decision {
	case exposure.Pass:
		os.Exit(0)
	case exposure.Fail:
		os.Exit(1)
	default:
		os.Exit(2)
	}
}
