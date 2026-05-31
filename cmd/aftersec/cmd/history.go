package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View revision history",
	Run: func(cmd *cobra.Command, args []string) {
		history, err := globalMgr.GetHistory()
		if err != nil {
			fmt.Println("Error fetching history:", err)
			os.Exit(1)
		}

		if len(history) == 0 {
			fmt.Println("No history found.")
			return
		}

		fmt.Println("Commit History:")
		for i, h := range history {
			fmt.Printf("[%d] %s\n", i, h.Timestamp.Format("2006-01-02 15:04:05"))
		}
	},
}

func init() {
	rootCmd.AddCommand(historyCmd)
}
