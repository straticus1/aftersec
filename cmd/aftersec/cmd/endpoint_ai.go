package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/spf13/cobra"
	
	"aftersec/pkg/ai"
)

var endpointAICmd = &cobra.Command{
	Use:   "endpoint-ai",
	Short: "Manage the local Endpoint AI behavioral anomaly detection engine",
	Long:  "Commands to view the status of the local ML baseline, manually trigger a training epoch, or force the engine into an enforcement state.",
}

var endpointAIStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View the status of the local ML behavioral baseline",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("--- Endpoint AI Status ---")
		fmt.Println(ai.Status())
	},
}

var endpointAITrainCmd = &cobra.Command{
	Use:   "train",
	Short: "Force a local ML training epoch over the vectorized observations",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Triggering local Neural Engine training epoch. This may take a few seconds and spike CPU/NPU usage...")
		err := ai.TriggerLocalTraining(context.Background())
		if err != nil {
			log.Fatalf("Training failed: %v", err)
		}
		fmt.Println("Training successful. Baseline updated.")
	},
}

func init() {
	endpointAICmd.AddCommand(endpointAIStatusCmd)
	endpointAICmd.AddCommand(endpointAITrainCmd)
	rootCmd.AddCommand(endpointAICmd)
}
