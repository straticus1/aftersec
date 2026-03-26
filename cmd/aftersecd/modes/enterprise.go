package modes

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"aftersec/pkg/forensics"
	"aftersec/pkg/scanners"
)

// RunEnterprise starts the daemon in enterprise mode
func RunEnterprise(cfg *client.ClientConfig, mgr storage.Manager) {
	log.Println("Starting AfterSec daemon in Enterprise Mode (gRPC Enabled)")

	grpcClient, err := client.NewEnterpriseClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize enterprise client: %v", err)
	}
	defer grpcClient.Close()

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

		if resp.PolicyUpdated {
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
				var idsToMark []int
				for _, ev := range batch {
					if id, ok := ev["id"].(int64); ok {
						idsToMark = append(idsToMark, int(id))
					}
				}
				if markErr := mgr.MarkTelemetrySynced(idsToMark); markErr != nil {
					log.Printf("Failed to mark telemetry synced locally: %v", markErr)
				} else {
					log.Printf("✅ Automatically Synced %d telemetry events to Enterprise Upstream Server.", len(idsToMark))
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
