package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"aftersec/pkg/forensics"
)

var analyzePkgCmd = &cobra.Command{
	Use:   "analyze-pkg [PKG Path]",
	Short: "Perform deep script extraction on macOS .pkg installers",
	Long: `Invokes the AfterSec forensic engine to intelligently expand macOS Installer Packages (XAR structure) in a safe sandbox and rip out pre/post install bash scripts for deep reverse-shell analytics.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pkgPath := args[0]
		
		fmt.Printf("📦 Ripping Open XAR Installer Archive: %s\n", pkgPath)
		res, err := forensics.AnalyzeInstaller(context.Background(), pkgPath)
		if err != nil {
			fmt.Printf("❌ Archival extraction sequence failed: %v\n", err)
			os.Exit(1)
		}

		if res.Error != nil {
			fmt.Printf("❌ Failed to parse payload contents: %v\n", res.Error)
			os.Exit(1)
		}

		fmt.Println("\n--- 📜 Root-Level Installer Scripts Detected ---")
		if res.RawScriptsExtracted == 0 {
			fmt.Println("✅ Status: Clean and Safe")
			fmt.Println("   No preinstall or postinstall scripts were found executing as root.")
		} else {
			fmt.Printf("⚠️  Status: Root Operations Scheduled (%d scripts found)\n", res.RawScriptsExtracted)
			
			if res.PreinstallScript != "" {
				fmt.Println("\n[PREINSTALL ROOT HOOK]")
				fmt.Println(res.PreinstallScript)
			}
			
			if res.PostinstallScript != "" {
				fmt.Println("\n[POSTINSTALL ROOT HOOK]")
				fmt.Println(res.PostinstallScript)
			}
		}
		fmt.Println("------------------------------------------------")
	},
}

func init() {
	rootCmd.AddCommand(analyzePkgCmd)
}
