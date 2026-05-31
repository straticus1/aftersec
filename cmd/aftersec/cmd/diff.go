package cmd

import (
	"fmt"
	"os"

	"aftersec/pkg/core"
	"aftersec/pkg/scanners"
	"github.com/spf13/cobra"
)

var diffFormat string

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare current posture with the last committed state",
	Run: func(cmd *cobra.Command, args []string) {
		latest, err := globalMgr.GetLatest()
		if err != nil {
			fmt.Println("Error fetching history:", err)
			os.Exit(1)
		}

		scanner := scanners.NewMacOSScanner(globalMgr)
		current, err := scanner.Scan(nil)
		if err != nil {
			fmt.Println("Error scanning:", err)
			os.Exit(1)
		}

		if latest == nil {
			fmt.Println("No previous commits found. Everything is new.")
			printState(current)
			return
		}

		diff := core.CompareStates(latest, current)
		if !diff.HasChanges() {
			fmt.Println("No changes detected since the last commit.")
			return
		}

		fmt.Println("Changes detected:")
		for _, change := range diff.Changes {
			fmt.Println(" -", change)
		}
	},
}

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().StringVar(&diffFormat, "format", "human", "Diff format: human|unified|json")
}
