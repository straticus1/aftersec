package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"aftersec/pkg/client"
	"aftersec/pkg/forensics"
	"aftersec/pkg/plugins"
	"aftersec/pkg/selfprotect"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage Starlark security plugins",
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed Starlark plugins",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(home, ".aftersec", "scripts")
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		names := make([]string, 0)
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".star") {
				names = append(names, entry.Name())
			}
		}
		return printOutput(map[string]any{"count": plugins.NumStarlarkRules(), "scripts": names, "dir": dir})
	},
}

var forensicsCmd = &cobra.Command{
	Use:   "forensics",
	Short: "Advanced forensics commands (memory, syscalls, persistence)",
}

var forensicsPersistenceCmd = &cobra.Command{
	Use:   "persistence",
	Short: "Scan autostart persistence locations",
	RunE: func(cmd *cobra.Command, args []string) error {
		findings, err := forensics.ScanPersistenceMechanisms()
		if err != nil {
			return err
		}
		return printOutput(findings)
	},
}

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage security baselines",
}

var baselineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored security baselines",
	RunE: func(cmd *cobra.Command, args []string) error {
		history, err := globalMgr.GetHistory()
		if err != nil {
			return err
		}
		return printOutput(history)
	},
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate compliance reports from the latest baseline",
	RunE: func(cmd *cobra.Command, args []string) error {
		latest, err := globalMgr.GetLatest()
		if err != nil {
			return err
		}
		if latest == nil {
			return fmt.Errorf("no baseline is available; run a scan first")
		}
		return printOutput(latest)
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View AfterSec configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the loaded configuration with secrets redacted",
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalCfg == nil {
			return fmt.Errorf("configuration is unavailable")
		}
		copyCfg := *globalCfg
		if copyCfg.Server != nil {
			serverCopy := *copyCfg.Server
			serverCopy.TLS.Key = redact(serverCopy.TLS.Key)
			serverCopy.TLS.Cert = redact(serverCopy.TLS.Cert)
			copyCfg.Server = &serverCopy
		}
		raw, err := yaml.Marshal(&copyCfg)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(raw))
		return nil
	},
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Control the AfterSec background daemon",
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon PID file status",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := ""
		if globalCfg != nil {
			path = globalCfg.Daemon.SelfProtection.PIDFile
		}
		info := map[string]any{"pid_file": path, "running": false}
		if path != "" {
			raw, err := os.ReadFile(path)
			if err == nil {
				info["pid"] = strings.TrimSpace(string(raw))
				info["running"] = true
			} else if !os.IsNotExist(err) {
				if err == selfprotect.ErrUnsafeWatchdogConfig {
					return err
				}
				return err
			}
		}
		return printOutput(info)
	},
}

var enrollCmd = &cobra.Command{
	Use:   "enroll <code>",
	Short: "Enroll this endpoint with a hardware attestation quote",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalCfg == nil || globalCfg.Mode != client.ModeEnterprise {
			return fmt.Errorf("enterprise mode is required for enrollment")
		}
		if len(args) != 1 || args[0] == "" || globalCfg.TenantID == "" || globalCfg.Server == nil || globalCfg.Server.TLS.CA == "" || globalCfg.Storage.Path == "" {
			return fmt.Errorf("enrollment code, tenant id, management CA, and storage path are required")
		}
		caPEM, err := os.ReadFile(globalCfg.Server.TLS.CA)
		if err != nil {
			return fmt.Errorf("read management CA: %w", err)
		}
		if len(caPEM) == 0 || len(caPEM) > 1<<20 {
			return fmt.Errorf("management CA is empty or too large")
		}
		provider, err := client.NewHardwareEvidenceProvider()
		if err != nil {
			return fmt.Errorf("hardware attestation is required: %w", err)
		}
		hardwareID, err := provider.Prepare(cmd.Context())
		if err != nil {
			return fmt.Errorf("hardware attestation is required: %w", err)
		}
		store, err := client.NewPlatformCredentialStore("production", globalCfg.Storage.Path, hardwareID)
		if err != nil {
			return err
		}
		grpcClient, err := client.NewEnterpriseClient(globalCfg)
		if err != nil {
			return err
		}
		defer grpcClient.Close()
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("read hostname: %w", err)
		}
		resp, err := grpcClient.EnrollAttested(cmd.Context(), provider, store, caPEM, client.EnrollmentDetails{
			OrganizationID: globalCfg.TenantID,
			EnrollmentCode: args[0],
			HardwareID:     hardwareID,
			Hostname:       hostname,
			OSVersion:      runtime.GOOS + "/" + runtime.GOARCH,
			AgentVersion:   "1.0.0",
		})
		if err != nil {
			return err
		}
		return printOutput(map[string]any{"enrolled": true, "tenant_id": resp.TenantId})
	},
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Show the AfterSec command surface",
	RunE: func(cmd *cobra.Command, args []string) error {
		names := make([]string, 0)
		for _, child := range rootCmd.Commands() {
			if !child.Hidden {
				names = append(names, child.Use)
			}
		}
		return printOutput(map[string]any{"commands": names})
	},
}

func redact(value string) string {
	if value == "" {
		return ""
	}
	return "[redacted]"
}

func printOutput(value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

func init() {
	pluginCmd.AddCommand(pluginListCmd)
	forensicsCmd.AddCommand(forensicsPersistenceCmd)
	baselineCmd.AddCommand(baselineListCmd)
	configCmd.AddCommand(configShowCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	rootCmd.AddCommand(pluginCmd)
	rootCmd.AddCommand(forensicsCmd)
	rootCmd.AddCommand(baselineCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(shellCmd)
}
