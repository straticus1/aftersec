package cmd

import (
	"aftersec/pkg/darkapi"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func init() {
	var path, base string
	cloud := &cobra.Command{Use: "cloud", Short: "Enroll and report to DarkAPI with a shared host identity", PersistentPreRunE: func(*cobra.Command, []string) error { return nil }}
	cloud.PersistentFlags().StringVar(&path, "credentials", darkapi.DefaultCredentialPath(), "protected Aftersec device credential file")
	cloud.PersistentFlags().StringVar(&base, "url", "https://api.darkapi.io", "DarkAPI HTTPS base URL")
	cloud.AddCommand(&cobra.Command{Use: "enroll", Short: "Consume an owner-issued app enrollment token", RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := darkapi.New(darkapi.Credentials{BaseURL: base})
		if err != nil {
			return err
		}
		if err := client.Enroll(cmd.Context(), os.Getenv("AFTERSEC_DARKAPI_ENROLLMENT_TOKEN"), path, "dev"); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), client.DeviceID())
		return nil
	}})
	cloud.AddCommand(&cobra.Command{Use: "status", Short: "Verify agent authentication and fetch reporting configuration", RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := darkapi.Load(path)
		if err != nil {
			return err
		}
		cfg, err := client.Config(cmd.Context())
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(cfg)
	}})
	rootCmd.AddCommand(cloud)
}
