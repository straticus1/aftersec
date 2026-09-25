package modes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"aftersec/pkg/compliance"
	"aftersec/pkg/core"
)

// publishCompliance signs the scan that just finished and, when a pack is
// configured, runs that pack with the same evidence key. A disabled
// compliance section does nothing. A required failure stops the daemon.
func publishCompliance(cfg *client.ClientConfig, endpointID string, state *core.SecurityState, mgr storage.Manager) {
	if cfg == nil || !cfg.Daemon.Compliance.Enabled {
		return
	}
	if err := writeCompliance(cfg, endpointID, state, mgr); err != nil {
		log.Printf("compliance evidence failed: %v", err)
		if cfg.Daemon.Compliance.Required {
			log.Fatalf("required compliance evidence failed: %v", err)
		}
	}
}

func writeCompliance(cfg *client.ClientConfig, endpointID string, state *core.SecurityState, mgr storage.Manager) error {
	if mgr == nil || state == nil || cfg.TenantID == "" || endpointID == "" {
		return compliance.ErrInvalidPack
	}
	key, err := compliance.LoadPrivateKey(cfg.Daemon.Compliance.EvidencePrivateKeyFile)
	if err != nil {
		return err
	}
	signed, err := compliance.PostureEvidence(cfg.TenantID, endpointID, state.Timestamp, state.Findings, key)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	if err := mgr.LogTelemetryEvent("compliance", "posture_evidence", "info", string(raw)); err != nil {
		return fmt.Errorf("store posture evidence: %w", err)
	}
	if cfg.Daemon.Compliance.PackPath == "" {
		return nil
	}
	publicKey, err := compliance.LoadPublicKey(cfg.Daemon.Compliance.PackPublicKeyFile)
	if err != nil {
		return err
	}
	pack, err := loadPack(cfg.Daemon.Compliance.PackPath)
	if err != nil {
		return err
	}
	job := compliance.Job{
		PublicKey: publicKey, EvidenceKey: key, TenantID: cfg.TenantID, EndpointID: endpointID,
		Runner: compliance.Runner{Executor: compliance.CommandExecutor{}, Timeout: 10 * time.Second, MaxOutputBytes: 4096},
		Submit: func(_ context.Context, evidence compliance.SignedEvidence) error {
			body, err := json.Marshal(evidence)
			if err != nil {
				return err
			}
			return mgr.LogTelemetryEvent("compliance", "pack_evidence", "info", string(body))
		},
	}
	_, err = job.Run(context.Background(), pack, cfg.Daemon.Compliance.ActiveVersion, time.Now().UTC())
	return err
}

func loadPack(path string) (compliance.SignedPack, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return compliance.SignedPack{}, fmt.Errorf("read compliance pack: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 1<<20 {
		return compliance.SignedPack{}, compliance.ErrInvalidPack
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return compliance.SignedPack{}, fmt.Errorf("read compliance pack: %w", err)
	}
	var pack compliance.SignedPack
	if err := json.Unmarshal(data, &pack); err != nil {
		return compliance.SignedPack{}, compliance.ErrInvalidPack
	}
	return pack, nil
}
