package cmd

import (
	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	outputFmt  string
	globalCfg  *client.ClientConfig
	globalMgr  storage.Manager
)

var rootCmd = &cobra.Command{
	Use:   "aftersec",
	Short: "AfterSec MacOS Security Posture Manager",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		if cfgFile != "" {
			globalCfg, err = client.LoadConfig(cfgFile)
		} else {
			home, _ := os.UserHomeDir()
			defaultPath := home + "/.aftersec/config.yaml"
			globalCfg, err = client.LoadConfig(defaultPath)
		}

		if err != nil {
			fmt.Printf("Warning: failed to load config (%v), falling back to default\n", err)
			globalCfg = client.DefaultClientConfig()
		}

		if globalCfg.Mode == client.ModeEnterprise {
			globalMgr, err = storage.NewCacheManager(globalCfg)
			if err != nil {
				return fmt.Errorf("failed to init enterprise storage: %w", err)
			}
		} else {
			globalMgr, err = storage.NewSQLiteManager(globalCfg.Storage.Path)
			if err != nil {
				return fmt.Errorf("failed to init local storage: %w", err)
			}
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.aftersec/config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "output format: table|json|yaml|csv")
}
