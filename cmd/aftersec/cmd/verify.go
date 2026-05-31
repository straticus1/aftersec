package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"aftersec/pkg/forensics"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [Bundle Path]",
	Short: "Perform deep cryptographic verification of a macOS app container",
	Long: `Invokes the AfterSec forensic engine to check the integrity of an .app or .pkg container.
Detects Broken Seals, Dylib Hijacking, and revoked Developer Certificates.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appPath := args[0]
		
		fmt.Printf("🔍 Scanning Cryptographic Container: %s\n", appPath)
		res, err := forensics.VerifyMacBundle(context.Background(), appPath)
		if err != nil {
			fmt.Printf("❌ Failed to initiate verification: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\n--- 🛡️ App Signature Report ---")
		if res.IsValid {
			fmt.Println("✅ Status: STRUCTURALLY SOUND & TRUSTED")
			fmt.Printf("   Developer Authority: %s\n", res.Authority)
			fmt.Printf("   Team ID:             %s\n", res.TeamID)
		} else {
			fmt.Println("❌ Status: SEVERELY COMPROMISED / UNTRUSTED")
			if res.IsAdHoc {
				fmt.Println("   Type: Ad-Hoc (Self-Signed / Untrusted)")
			}
			if res.Authority != "" {
				fmt.Printf("   Developer Authority: %s\n", res.Authority)
				fmt.Printf("   Team ID:             %s\n", res.TeamID)
			}
			fmt.Println("\n⚠️  Issues Detected:")
			for _, issue := range res.Issues {
				fmt.Printf("   - %s\n", issue)
			}
		}
		fmt.Println("--------------------------------")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
