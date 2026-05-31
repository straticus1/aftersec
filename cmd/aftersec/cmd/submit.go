package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/client"
)

var submitCmd = &cobra.Command{
	Use:   "submit [FILE]",
	Short: "Submit a suspicious file to the enterprise detonation queue",
	Long: `Securely forwards a sample to the configured enterprise backend
for deep cloud-based execution and behavioral analysis.

Requires Enterprise Mode configured via 'aftersec enroll'.

Example:
  aftersec submit /tmp/suspicious_payload.bin`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetFile := args[0]

		fmt.Printf("☁️  AfterSec Cloud Detonation Submission\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("Target: %s\n\n", targetFile)

		f, err := os.Open(targetFile)
		if err != nil {
			fmt.Printf("❌ Failed to read file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		home, _ := os.UserHomeDir()
		configPath := filepath.Join(home, ".aftersec", "config.yaml")
		cfg, err := client.LoadConfig(configPath)
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			os.Exit(1)
		}

		if cfg.Server == nil || cfg.Server.Address == "" {
			fmt.Println("❌ Enterprise Server not configured.")
			fmt.Println("   Please run 'aftersec enroll <TOKEN>' first.")
			os.Exit(1)
		}

		urlStr := fmt.Sprintf("%s/api/v1/detonate", cfg.Server.Address)
		req, err := http.NewRequest("POST", urlStr, f)
		if err != nil {
			fmt.Printf("❌ Internal error generating request: %v\n", err)
			os.Exit(1)
		}
		
		req.Header.Set("Authorization", "Bearer "+cfg.Server.EnrollmentToken)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-File-Name", filepath.Base(targetFile))

		fmt.Println("📡 Forwarding sample to Enterprise Detonation Queue...")

		httpClient := &http.Client{Timeout: 5 * time.Minute}
		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Printf("❌ Server unreachable or connection failed: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			fmt.Printf("❌ Authentication failed (%d). Check your enrollment token.\n", resp.StatusCode)
			os.Exit(1)
		}

		var result struct {
			Success bool   `json:"success"`
			ID      string `json:"analysis_id"`
			Message string `json:"message"`
			Verdict string `json:"verdict,omitempty"`
			Score   int    `json:"score,omitempty"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			// Fallback if not standard JSON
			if resp.StatusCode >= 400 {
				fmt.Printf("❌ Submission rejected by server (HTTP %d)\n", resp.StatusCode)
			} else {
				fmt.Println("✅ Submission successful, but couldn't parse response format.")
			}
			os.Exit(1)
		}

		if !result.Success && result.Message != "" {
			fmt.Printf("❌ Submission Failed: %s\n", result.Message)
			os.Exit(1)
		}

		fmt.Println("✅ Sample accepted for analysis!")
		if result.ID != "" {
			fmt.Printf("   Analysis ID: %s\n", result.ID)
			fmt.Printf("   You can track this analysis in your Enterprise Dashboard.\n")
		}

		// If synchronous synchronous detonation completed quickly
		if result.Verdict != "" {
			fmt.Printf("\n⚡ Immediate Verdict: %s (Score: %d)\n", result.Verdict, result.Score)
		}
		
		fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	},
}

func init() {
	rootCmd.AddCommand(submitCmd)
}
