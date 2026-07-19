package modes

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"aftersec/pkg/forensics"
	"aftersec/pkg/response"
	"aftersec/pkg/scanners"
	"aftersec/pkg/telemetry"
)

// RunEnterprise starts the daemon in enterprise mode
func RunEnterprise(cfg *client.ClientConfig, mgr storage.Manager) {
	log.Println("Starting AfterSec daemon in Enterprise Mode (gRPC Enabled)")

	grpcClient, err := client.NewEnterpriseClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize enterprise client: %v", err)
	}
	defer grpcClient.Close()

	// The command channel is enabled only with an explicitly provisioned
	// Ed25519 verification key. Missing or malformed key material fails closed;
	// the daemon never accepts unsigned control actions.
	if cfg.Server.ActionVerificationKey != "" {
		keyBytes, keyErr := os.ReadFile(cfg.Server.ActionVerificationKey)
		if keyErr != nil || len(keyBytes) != ed25519.PublicKeySize {
			log.Printf("remote command channel disabled: action verification key is unavailable or invalid")
		} else {
			quarantine := response.NewQuarantineManager(response.NewPlatformFirewall())
			runner := response.NewSystemActionRunner(quarantine, 1<<20)
			executor := response.NewActionExecutor(ed25519.PublicKey(keyBytes), cfg.TenantID, "HW-"+hostnameOrUnknown(), runner, 1<<20, time.Now)
			processor := client.NewCommandProcessor(cfg.TenantID, "HW-"+hostnameOrUnknown(), executor, 1<<20)
			go func() {
				streamCtx := context.Background()
				stream, streamErr := grpcClient.ConnectCommandStream(streamCtx)
				if streamErr != nil {
					log.Printf("remote command stream unavailable; commands remain disabled: %v", streamErr)
					return
				}
				if streamErr = client.RunCommandLoop(streamCtx, stream, processor); streamErr != nil {
					log.Printf("remote command stream stopped: %v", streamErr)
				}
			}()
		}
	}

	if cfg.TenantID == "" {
		log.Fatalf("Tenant ID is not configured. Please run 'aftersec enroll' first.")
	}

	hostname, _ := os.Hostname()
	hwID := "HW-" + hostname // Stub for real hardware ID fetcher

	interval, err := time.ParseDuration(cfg.Daemon.Scheduling.ScanInterval)
	if err != nil || interval <= 0 {
		interval = 6 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	doHeartbeat := func() {
		log.Printf("[%s] executing secure enterprise environment scan", time.Now().Format(time.RFC3339))
		scanner := scanners.NewMacOSScanner(mgr)
		currentState, err := scanner.Scan(nil)
		if err != nil {
			log.Printf("scan failed: %v", err)
			return
		}

		if ruleBytes, err := os.ReadFile("/etc/aftersec/rules.star"); err == nil {
			log.Println("Evaluating remote Enterprise Starlark ruleset...")
			if err := forensics.EvaluateRules(string(ruleBytes), currentState); err != nil {
				log.Printf("Starlark execution failed: %v", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := grpcClient.Heartbeat(ctx, cfg.TenantID, hwID, "ONLINE")
		if err != nil {
			log.Printf("Heartbeat failed: %v", err)
			return
		}

		if strings.HasPrefix(resp.Action, "RUN_SIGMA::") {
			log.Println("⚡️ Fleet Command Received: RUN_SIGMA")
			sigmaB64 := strings.TrimPrefix(resp.Action, "RUN_SIGMA::")
			if yamlBytes, err := base64.StdEncoding.DecodeString(sigmaB64); err == nil {
				if rule, err := telemetry.ParseSigmaRule(yamlBytes); err == nil {
					sqliteMgr, ok := mgr.(*storage.SQLiteManager)
					if ok {
						events, _ := telemetry.RunHunt(sqliteMgr, rule)
						if len(events) > 0 {
							log.Printf("🚨 Sigma Hunt MATCHED %d internal events! Queuing for upload...", len(events))
							detailsBytes, _ := json.Marshal(events)
							mgr.LogTelemetryEvent("Sigma Fleet Hunt", "sigma_match", "CRITICAL", string(detailsBytes))
						} else {
							log.Println("✅ Sigma Hunt finished safely with no matches.")
						}
					}
				}
			}
		} else if resp.PolicyUpdated {
			log.Printf("Policy updated! New hash: %s. Action required: %s", resp.NewPolicyHash, resp.Action)
			// In a full implementation, we would instruct `mgr` (CacheManager) to fetch the new Starlark policies
		} else {
			log.Printf("Heartbeat OK - System In-Sync")
		}
	}

	// Initial Heartbeat
	doHeartbeat()

	// Enterprise Telemetry Sync Queue
	go func() {
		syncTicker := time.NewTicker(2 * time.Minute)
		defer syncTicker.Stop()

		for range syncTicker.C {
			batch, err := mgr.GetUnsyncedTelemetry(100)
			if err != nil || len(batch) == 0 {
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			processedCount, err := grpcClient.StreamTelemetryBatch(ctx, cfg.TenantID, hwID, batch)
			cancel()

			if err != nil {
				log.Printf("Telemetry sync failed: %v", err)
				continue
			}

			if processedCount > 0 {
				idsToMark, ackErr := client.AcknowledgedTelemetryIDs(batch, processedCount)
				if ackErr != nil {
					log.Printf("Rejected invalid telemetry acknowledgment: %v", ackErr)
					continue
				}
				if markErr := mgr.MarkTelemetrySynced(idsToMark); markErr != nil {
					log.Printf("Failed to mark telemetry synced locally: %v", markErr)
				} else {
					log.Printf("✅ Automatically Synced %d telemetry events to Enterprise Upstream Server.", processedCount)
				}
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			go doHeartbeat()
		case sig := <-sigChan:
			log.Printf("received signal %v, shutting down", sig)
			return
		}
	}
}

func hostnameOrUnknown() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "unknown"
	}
	return hostname
}
