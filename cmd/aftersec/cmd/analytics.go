package cmd

import (
	"aftersec/pkg/ai"
	"context"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var analyticsCmd = &cobra.Command{
	Use:   "analytics",
	Short: "Run Deep Behavior Analytics on local telemetry via AI Swarm",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running Deep Behavior Analytics against local SQLite telemetry...")
		engine := ai.NewCorrelationEngine(globalMgr)
		risks, err := engine.Run()
		if err != nil {
			log.Fatalf("Analytics engine failed: %v", err)
		}

		if len(risks) == 0 {
			fmt.Println("✅ Safe! No complex behavioral attack chains detected.")
			return
		}

		for _, r := range risks {
			fmt.Printf("\n🚨 COMPREHENSIVE THREAT CHAIN DETECTED: %s\n", r.RuleName)
			fmt.Printf("   Cumulative Risk Score: %.1f\n", r.ThreatScore)
			fmt.Printf("   Context: %s\n", r.Context)
			
			fmt.Println("   --- AI Swarm Escalation Analysis ---")
			analysis, err := engine.EscalateToSwarm(context.Background(), r)
			if err != nil {
				fmt.Printf("   [Swarm Error: %v]\n", err)
			} else {
				fmt.Printf("   %s\n", analysis)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(analyticsCmd)
}
