package cmd

import (
	"fmt"
	"os"

	"aftersec/pkg/core"
	"aftersec/pkg/scanners"
	"github.com/spf13/cobra"
)

var fixDryRun bool

var fixCmd = &cobra.Command{
	Use:   "fix [rule_name]",
	Short: "Automatically remediate a specific failing security rule",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ruleName := args[0]
		scanner := scanners.NewMacOSScanner(globalMgr)
		currentState, err := scanner.Scan(nil)
		if err != nil {
			fmt.Println("Error scanning current state:", err)
			os.Exit(1)
		}

		if fixDryRun {
			fmt.Printf("Dry Run: Would fix rule '%s'\n", ruleName)
			return
		}

		err = core.RemediateFinding(currentState, ruleName)
		if err != nil {
			fmt.Println("Failed to fix rule:", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully remediated rule: '%s'\n", ruleName)
	},
}

func init() {
	rootCmd.AddCommand(fixCmd)
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Preview the remediation without applying it")
}
