package cmd

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/darkapi"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
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
	openQueue := func() (*darkapi.Exporter, error) {
		client, err := darkapi.Load(path)
		if err != nil {
			return nil, err
		}
		return darkapi.Open(nil, client, filepath.Join(filepath.Dir(path), "darkapi-outbox.sqlite"))
	}
	cloud.AddCommand(&cobra.Command{Use: "queue", Short: "Show durable delivery counters and quarantined event IDs", RunE: func(cmd *cobra.Command, _ []string) error {
		queue, err := openQueue()
		if err != nil {
			return err
		}
		defer queue.Close()
		stats, err := queue.Stats()
		if err != nil {
			return err
		}
		quarantined, err := queue.Quarantined()
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"stats": stats, "quarantined": quarantined})
	}})
	cloud.AddCommand(&cobra.Command{Use: "retry EVENT_ID", Args: cobra.ExactArgs(1), Short: "Requeue a quarantined event unchanged after resolving its rejection", RunE: func(cmd *cobra.Command, args []string) error {
		queue, err := openQueue()
		if err != nil {
			return err
		}
		defer queue.Close()
		return queue.Requeue(args[0])
	}})
	var source string
	backfill := &cobra.Command{Use: "backfill", Short: "Import existing local journal and posture into the durable DarkAPI queue", RunE: func(cmd *cobra.Command, _ []string) error {
		if source == "" {
			return fmt.Errorf("--source must identify an existing Aftersec storage directory")
		}
		if _, err := os.Stat(filepath.Join(source, "aftersec.db")); err != nil {
			return err
		}
		manager, err := storage.NewSQLiteManager(source)
		if err != nil {
			return err
		}
		defer manager.Close()
		client, err := darkapi.Load(path)
		if err != nil {
			return err
		}
		queue, err := darkapi.Open(manager, client, filepath.Join(filepath.Dir(path), "darkapi-outbox.sqlite"))
		if err != nil {
			return err
		}
		defer queue.Close()
		total := 0
		for {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			n, err := queue.SyncSource()
			if err != nil {
				return err
			}
			total += n
			if n == 0 {
				break
			}
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"source_records_imported": total, "device_id": queue.DeviceID()})
	}}
	backfill.Flags().StringVar(&source, "source", "", "existing Aftersec storage directory")
	cloud.AddCommand(backfill)
	rootCmd.AddCommand(cloud)
}
