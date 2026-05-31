package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var darkscanCmd = &cobra.Command{
	Use:   "darkscan",
	Short: "DarkScan platform commands for malware detection and analysis",
	Long: `Comprehensive malware detection platform with multiple features:

• Malware Scanning: Multi-engine threat detection (YARA, ClamAV, CAPA, Viper)
• Privacy Scanner: Browser tracking and telemetry detection
• Quarantine: Isolated file storage with encryption
• File Type Detection: Magic byte analysis and spoofing detection
• Rule Management: YARA rule repositories and auto-updates
• Scan Profiles: Preset configurations (quick, standard, deep, forensic, safe)
• History: Scan history and deduplication

Available commands:
  scan        - Scan files and directories for malware
  privacy     - Privacy and telemetry scanning
  quarantine  - Manage quarantined files
  rules       - YARA rule repository management
  profiles    - Manage scan profiles
  history     - View scan history
  filetype    - File type identification and spoofing detection
  status      - DarkScan platform status

Examples:
  aftersec darkscan scan /suspicious/file.exe
  aftersec darkscan privacy scan --browsers chrome,firefox
  aftersec darkscan quarantine list
  aftersec darkscan rules update
  aftersec darkscan status`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'aftersec darkscan --help' to see available commands")
	},
}

func init() {
	rootCmd.AddCommand(darkscanCmd)
}
