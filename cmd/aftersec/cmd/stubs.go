package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage Starlark security plugins",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Plugin management is coming in a future update.")
	},
}

var forensicsCmd = &cobra.Command{
	Use:   "forensics",
	Short: "Advanced forensics commands (memory, syscalls, persistence)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Forensics suite is coming in a future update.")
	},
}

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage security baselines",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Advanced baseline management is coming in a future update. Use 'commit' and 'restore' for now.")
	},
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate compliance reports (CIS, NIST, SOC2)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Reporting engine is coming in a future update.")
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View and edit AfterSec configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Configuration management is coming in a future update.")
	},
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Control the AfterSec background daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Daemon control is coming in a future update.")
	},
}

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll this endpoint into an AfterSec Management Server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Enterprise enrollment is coming in a future update.")
	},
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Launch the AfterSec Interactive Shell",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("Interactive Shell is coming in a future update.")
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
	rootCmd.AddCommand(forensicsCmd)
	rootCmd.AddCommand(baselineCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(shellCmd)
}
