package cmd

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aftersec/pkg/breakglass"
	"aftersec/pkg/response"

	"github.com/spf13/cobra"
)

func endpointID() string {
	host, _ := os.Hostname()
	return "HW-" + host
}

func loadBreakGlassGuard() (*breakglass.Guard, error) {
	if globalCfg == nil {
		return nil, fmt.Errorf("configuration is unavailable")
	}
	path := filepath.Join(globalCfg.Storage.Path, "breakglass.state")
	if !filepath.IsAbs(path) {
		return nil, breakglass.ErrInvalidOverride
	}
	return breakglass.NewGuard(path, globalCfg.TenantID, endpointID(), time.Now)
}

var breakGlassCmd = &cobra.Command{
	Use:   "break-glass",
	Short: "Apply or inspect a signed, time-boxed policy override",
}

var breakGlassStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether a break-glass window is active",
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := loadBreakGlassGuard()
		if err != nil {
			return err
		}
		st, ok := g.Status()
		return printOutput(map[string]any{"active": ok, "state": st})
	},
}

var breakGlassApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a server-signed break-glass token on this endpoint",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := cmd.Flags().GetString("token")
		if err != nil || token == "" {
			return fmt.Errorf("token is required")
		}
		if globalCfg == nil || globalCfg.Server == nil || globalCfg.Server.ActionVerificationKey == "" {
			return fmt.Errorf("action verification key is required")
		}
		keyBytes, err := os.ReadFile(globalCfg.Server.ActionVerificationKey)
		if err != nil || len(keyBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("action verification key is unavailable or invalid")
		}
		g, err := loadBreakGlassGuard()
		if err != nil {
			return err
		}
		runner := response.NewSystemActionRunner(nil, 1<<20).WithBreakGlass(g)
		exec := response.NewActionExecutor(ed25519.PublicKey(keyBytes), globalCfg.TenantID, endpointID(), runner, 1<<20, time.Now)
		out, err := exec.Execute(context.Background(), token, nil)
		if err != nil {
			return err
		}
		return printOutput(map[string]any{"status": string(out)})
	},
}

var breakGlassEndCmd = &cobra.Command{
	Use:   "end",
	Short: "End an active window and restore enforcement",
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := loadBreakGlassGuard()
		if err != nil {
			return err
		}
		if err := g.End(); err != nil {
			return err
		}
		return printOutput(map[string]any{"active": false})
	},
}

func init() {
	breakGlassApplyCmd.Flags().String("token", "", "signed break-glass token from the management server")
	breakGlassCmd.AddCommand(breakGlassStatusCmd)
	breakGlassCmd.AddCommand(breakGlassApplyCmd)
	breakGlassCmd.AddCommand(breakGlassEndCmd)
	rootCmd.AddCommand(breakGlassCmd)
}
