package cmd

import (
	stdcontext "context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/client"
	"aftersec/pkg/darkscan"
)

var (
	quarantineDestination string
	quarantineAll         bool
)

var quarantineCmd = &cobra.Command{
	Use:   "quarantine",
	Short: "Manage quarantined files",
	Long: `Quarantine management operations:

• List quarantined files with metadata
• View details of specific quarantine entries
• Restore files from quarantine
• Permanently delete quarantined files
• Clean old quarantine entries

Quarantined files are isolated with optional AES-256-GCM encryption
and tracked in a SQLite database.`,
}

var quarantineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all quarantined files",
	Long: `Display all quarantined files with metadata:
  • Quarantine ID
  • Original path
  • Quarantine date
  • File size
  • File hash (SHA256)
  • Detected threats
  • Encryption status

Example:
  aftersec darkscan quarantine list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		entries, err := scanner.ListQuarantine(ctx)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to list quarantine: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to list quarantine: %v\n", err)
			}
			os.Exit(1)
		}

		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: true,
				Data:    entries,
			})
			return
		}

		if len(entries) == 0 {
			fmt.Println("📦 Quarantine is empty")
			return
		}

		fmt.Printf("📦 Quarantined Files (%d total)\n\n", len(entries))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tOriginal Path\tDate\tSize\tThreats\tEncrypted")
		fmt.Fprintln(w, "──\t─────────────\t────\t────\t───────\t─────────")

		for _, entry := range entries {
			threats := fmt.Sprintf("%d", len(entry.Threats))
			encrypted := "No"
			if entry.Encrypted {
				encrypted = "Yes"
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				entry.QuarantineID[:16]+"...",
				truncatePath(entry.OriginalPath, 40),
				entry.QuarantinedAt.Format("2006-01-02 15:04"),
				formatFileSize(entry.FileSize),
				threats,
				encrypted,
			)
		}
		w.Flush()
	},
}

var quarantineInfoCmd = &cobra.Command{
	Use:   "info [QUARANTINE_ID]",
	Short: "Show detailed information about a quarantined file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		quarantineID := args[0]
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		info, err := scanner.GetQuarantineInfo(ctx, quarantineID)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to get quarantine info: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to get quarantine info: %v\n", err)
			}
			os.Exit(1)
		}

		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: true,
				Data:    info,
			})
			return
		}

		fmt.Printf("📦 Quarantine Information\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		fmt.Printf("ID:            %s\n", info.QuarantineID)
		fmt.Printf("Original Path: %s\n", info.OriginalPath)
		fmt.Printf("Quarantined:   %s\n", info.QuarantinedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("File Size:     %s\n", formatFileSize(info.FileSize))
		fmt.Printf("SHA256 Hash:   %s\n", info.FileHash)
		fmt.Printf("Encrypted:     %v\n", info.Encrypted)

		if len(info.Threats) > 0 {
			fmt.Printf("\nDetected Threats (%d):\n", len(info.Threats))
			for i, threat := range info.Threats {
				fmt.Printf("  %d. %s (%s) - %s\n", i+1, threat.Name, threat.Severity, threat.Engine)
				if threat.Description != "" {
					fmt.Printf("     %s\n", threat.Description)
				}
			}
		}
	},
}

var quarantineRestoreCmd = &cobra.Command{
	Use:   "restore [QUARANTINE_ID]",
	Short: "Restore a quarantined file",
	Long: `Restore a file from quarantine to its original location or a custom destination.

⚠️  WARNING: Only restore files you trust! Restored files may be dangerous.

Examples:
  aftersec darkscan quarantine restore abc123...
  aftersec darkscan quarantine restore abc123... --destination /safe/location/file.exe`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		quarantineID := args[0]
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		// Get info first for confirmation
		info, err := scanner.GetQuarantineInfo(ctx, quarantineID)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to get quarantine info: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to get quarantine info: %v\n", err)
			}
			os.Exit(1)
		}

		destination := quarantineDestination
		if destination == "" {
			destination = info.OriginalPath
		}

		if outputFormat != "json" {
			fmt.Printf("⚠️  WARNING: Restoring potentially dangerous file!\n\n")
			fmt.Printf("Original Path: %s\n", info.OriginalPath)
			fmt.Printf("Restore To:    %s\n", destination)
			fmt.Printf("Threats:       %d detected\n\n", len(info.Threats))

			if !quarantineAll {
				fmt.Print("Are you sure you want to restore this file? (yes/no): ")
				var response string
				fmt.Scanln(&response)
				if response != "yes" {
					fmt.Println("Restore cancelled")
					return
				}
			}
		}

		err = scanner.RestoreQuarantined(ctx, quarantineID, destination)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to restore file: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to restore file: %v\n", err)
			}
			os.Exit(1)
		}

		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: true,
				Data: map[string]string{
					"quarantine_id": quarantineID,
					"restored_to":   destination,
				},
			})
		} else {
			fmt.Printf("✅ File restored to: %s\n", destination)
		}
	},
}

var quarantineDeleteCmd = &cobra.Command{
	Use:   "delete [QUARANTINE_ID]",
	Short: "Permanently delete a quarantined file",
	Long: `Permanently delete a file from quarantine.

⚠️  This action cannot be undone!

Examples:
  aftersec darkscan quarantine delete abc123...
  aftersec darkscan quarantine delete abc123... --yes`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		quarantineID := args[0]
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 30*time.Second)
		defer cancel()

		// Get info first for confirmation
		info, err := scanner.GetQuarantineInfo(ctx, quarantineID)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to get quarantine info: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to get quarantine info: %v\n", err)
			}
			os.Exit(1)
		}

		if outputFormat != "json" && !quarantineAll {
			fmt.Printf("⚠️  Permanently delete quarantined file?\n\n")
			fmt.Printf("Original Path: %s\n", info.OriginalPath)
			fmt.Printf("Quarantined:   %s\n\n", info.QuarantinedAt.Format("2006-01-02 15:04:05"))

			fmt.Print("Type 'DELETE' to confirm: ")
			var response string
			fmt.Scanln(&response)
			if response != "DELETE" {
				fmt.Println("Deletion cancelled")
				return
			}
		}

		err = scanner.DeleteQuarantined(ctx, quarantineID)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to delete quarantined file: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to delete: %v\n", err)
			}
			os.Exit(1)
		}

		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: true,
				Data: map[string]string{
					"quarantine_id": quarantineID,
					"status":        "deleted",
				},
			})
		} else {
			fmt.Printf("✅ Quarantined file permanently deleted\n")
		}
	},
}

var quarantineCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove old quarantined files",
	Long: `Remove quarantined files older than the specified retention period.

Default retention is 30 days (configured in ~/.aftersec/config.yaml)

Example:
  aftersec darkscan quarantine clean --older-than 30d`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		// Default to 30 days from config
		retentionDays := cfg.Quarantine.AutoDeleteDays
		if retentionDays == 0 {
			retentionDays = 30
		}

		olderThan := time.Duration(retentionDays) * 24 * time.Hour

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 2*time.Minute)
		defer cancel()

		count, err := scanner.CleanQuarantine(ctx, olderThan)
		if err != nil {
			if outputFormat == "json" {
				quarantineOutputJSON(JSONOutput{
					Success: false,
					Error:   fmt.Sprintf("Failed to clean quarantine: %v", err),
				})
			} else {
				fmt.Printf("❌ Failed to clean quarantine: %v\n", err)
			}
			os.Exit(1)
		}

		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: true,
				Data: map[string]interface{}{
					"deleted_count": count,
					"retention_days": retentionDays,
				},
			})
		} else {
			fmt.Printf("✅ Cleaned %d files older than %d days\n", count, retentionDays)
		}
	},
}

func init() {
	darkscanCmd.AddCommand(quarantineCmd)
	quarantineCmd.AddCommand(quarantineListCmd)
	quarantineCmd.AddCommand(quarantineInfoCmd)
	quarantineCmd.AddCommand(quarantineRestoreCmd)
	quarantineCmd.AddCommand(quarantineDeleteCmd)
	quarantineCmd.AddCommand(quarantineCleanCmd)

	quarantineRestoreCmd.Flags().StringVar(&quarantineDestination, "destination", "", "Custom restore destination (default: original path)")
	quarantineRestoreCmd.Flags().BoolVar(&quarantineAll, "yes", false, "Skip confirmation prompt")

	quarantineDeleteCmd.Flags().BoolVar(&quarantineAll, "yes", false, "Skip confirmation prompt")
}

// Helper functions
func loadDarkScanConfig() *darkscan.Config {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("❌ Failed to get home directory: %v\n", err)
		os.Exit(1)
	}

	configPath := filepath.Join(home, ".aftersec", "config.yaml")
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Daemon.DarkScan.Enabled {
		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: false,
				Error:   "DarkScan is disabled. Enable it in ~/.aftersec/config.yaml",
			})
		} else {
			fmt.Println("❌ DarkScan is disabled")
			fmt.Println("Enable it in ~/.aftersec/config.yaml under daemon.darkscan.enabled: true")
		}
		os.Exit(1)
	}

	return &cfg.Daemon.DarkScan
}

func initDarkScanClient(cfg *darkscan.Config) *darkscan.Client {
	scanner, err := darkscan.NewClient(cfg)
	if err != nil {
		if outputFormat == "json" {
			quarantineOutputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to initialize DarkScan: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to initialize DarkScan: %v\n", err)
		}
		os.Exit(1)
	}
	return scanner
}

func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}

func quarantineOutputJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
