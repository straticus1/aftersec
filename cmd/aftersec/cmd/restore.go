package cmd

import (
	"fmt"
	"os"
	"strconv"

	"aftersec/pkg/core"
	"aftersec/pkg/scanners"
	"github.com/spf13/cobra"
)

var restoreCmd = &cobra.Command{
	Use:   "restore [history_index]",
	Short: "Restore security settings to a previous baseline commit",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idx, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Invalid index format:", args[0])
			os.Exit(1)
		}
		
		history, err := globalMgr.GetHistory()
		if err != nil {
			fmt.Println("Error fetching history:", err)
			os.Exit(1)
		}
		if idx < 0 || idx >= len(history) {
			fmt.Printf("Index out of bounds. Must be between 0 and %d\n", len(history)-1)
			os.Exit(1)
		}
		targetState := history[idx]

		scanner := scanners.NewMacOSScanner(globalMgr)
		currentState, err := scanner.Scan(nil)
		if err != nil {
			fmt.Println("Error scanning current state:", err)
			os.Exit(1)
		}

		actions, err := core.RestoreToState(targetState, currentState)
		if err != nil {
			fmt.Println("Restore operation failed:", err)
			os.Exit(1)
		}

		if len(actions) == 0 {
			fmt.Println("System already matches or exceeds the security posture of this commit.")
			return
		}

		fmt.Println("Restore Actions Executed:")
		for _, action := range actions {
			fmt.Println(" -", action)
		}
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)
}
