package cmd

import (
	"fmt"
	"os"
	"time"

	"aftersec/pkg/core"
	"aftersec/pkg/scanners"
	"github.com/spf13/cobra"
)

var (
	scanProfile  string
	scanCategory string
	watchMode    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan the current macOS security posture",
	Run: func(cmd *cobra.Command, args []string) {
		runScan()

		if watchMode {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				fmt.Println("\n--- Watch Mode Update ---")
				runScan()
			}
		}
	},
}

func runScan() {
	if err := scanners.ValidateProfile(scanProfile); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	if !scanners.KnownCategory(scanCategory) {
		fmt.Printf("unknown scan category %q\n", scanCategory)
		os.Exit(2)
	}
	scanner := scanners.NewMacOSScanner(globalMgr)
	scanner.Profile = scanProfile
	state, err := scanner.Scan(nil)
	if err != nil {
		fmt.Println("Error scanning:", err)
		os.Exit(1)
	}

	if scanCategory != "all" && scanCategory != "" {
		var filtered []core.Finding
		for _, f := range state.Findings {
			if scanners.MatchCategory(scanCategory, f.Category) {
				filtered = append(filtered, f)
			}
		}
		state.Findings = filtered
	}

	printState(state)

	// Implement standard exit codes for scripting support
	for _, f := range state.Findings {
		if !f.Passed && (f.Severity == core.Critical || f.Severity == core.VeryHigh) {
			os.Exit(10)
		}
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&scanProfile, "profile", "standard", "Scan profile: quick|standard|thorough|custom")
	scanCmd.Flags().StringVar(&scanCategory, "category", "all", "Category filter: system|network|filesystem|all")
	scanCmd.Flags().BoolVar(&watchMode, "watch", false, "Continuous monitoring mode")
}
