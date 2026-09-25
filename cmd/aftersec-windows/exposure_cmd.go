package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"aftersec/pkg/exposure"
)

func runExposure() {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "This scanner requires Windows.")
		os.Exit(2)
	}
	report := exposure.Collect("windows", func(name string, args ...string) (string, bool) {
		if name != "windows-firewall" {
			return "", false
		}
		ctx := context.Background()
		output, err := runPowerShell(ctx, powershellPreamble+firewallScript)
		if err != nil {
			return "", false
		}
		text := string(output)
		if len(text) > 0 && text[len(text)-1] == '\n' {
			text = text[:len(text)-1]
		}
		return text, true
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
