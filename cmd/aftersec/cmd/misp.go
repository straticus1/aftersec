package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"aftersec/pkg/client"
	"aftersec/pkg/threatintel"
)

var mispCmd = &cobra.Command{
	Use:   "misp",
	Short: "Manage MISP (Malware Information Sharing Platform) integration",
}

var mispInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show MISP connection status and fetch active IDS attributes",
	Run: func(cmd *cobra.Command, args []string) {
		home, _ := os.UserHomeDir()
		configPath := filepath.Join(home, ".aftersec", "config.yaml")

		cfg, err := client.LoadConfig(configPath)
		if err != nil {
			fmt.Printf("❌ Failed to load local config: %v\n", err)
			os.Exit(1)
		}

		if !cfg.Daemon.ThreatIntel.MISP.Enabled {
			fmt.Println("ℹ️  MISP Integration is currently Disabled in ~/.aftersec/config.yaml")
			return
		}

		mispCfg := &cfg.Daemon.ThreatIntel.MISP
		if mispCfg.BaseURL == "" || mispCfg.AuthKey == "" {
			fmt.Println("❌ MISP Base URL or Auth Key is not correctly configured.")
			return
		}

		fmt.Printf("📡 Connecting to MISP Instance: %s\n", mispCfg.BaseURL)
		
		mispClient := threatintel.NewMISPClient(mispCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := mispClient.Ping(ctx); err != nil {
			fmt.Printf("❌ MISP Connection Failed: %v\n", err)
			return
		}
		fmt.Println("✅ MISP Authentication Successful")

		// Fetch active attributes
		fmt.Println("🔍 Fetching active IDS network/file attributes...")
		attrs, err := mispClient.SearchAttributes(ctx, "")
		if err != nil {
			fmt.Printf("⚠️  Failed to fetch MISP attributes: %v\n", err)
			return
		}

		fmt.Printf("📊 Total Active IDS Indicators: %d\n", len(attrs))
		
		if len(attrs) > 0 {
			fmt.Println("\nRecent Top Indicators:")
			max := len(attrs)
			if max > 5 {
				max = 5
			}
			for i := 0; i < max; i++ {
				attr := attrs[i]
				fmt.Printf("  • [%s] %s: %s\n", attr.Category, attr.Type, attr.Value)
			}
		}
	},
}

func init() {
	mispCmd.AddCommand(mispInfoCmd)
	rootCmd.AddCommand(mispCmd)
}
