package cmd

import (
	"fmt"
	"os"

	"aftersec/pkg/scanners"
	"github.com/spf13/cobra"
)

var commitMessage string
var commitTag string

var commitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Save the current security posture as a baseline commit",
	Run: func(cmd *cobra.Command, args []string) {
		scanner := scanners.NewMacOSScanner(globalMgr)
		current, err := scanner.Scan(nil)
		if err != nil {
			fmt.Println("Error scanning:", err)
			os.Exit(1)
		}

		if err := globalMgr.SaveCommit(current); err != nil {
			fmt.Println("Error saving commit:", err)
			os.Exit(1)
		}

		fmt.Println("Successfully committed current security posture.")
	},
}

func init() {
	rootCmd.AddCommand(commitCmd)
	commitCmd.Flags().StringVarP(&commitMessage, "message", "m", "", "Commit message reason")
	commitCmd.Flags().StringVarP(&commitTag, "tag", "t", "", "Tag for this baseline")
}
