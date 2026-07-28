package main

import (
	"aftersec/cmd/aftersecd/modes"
	"aftersec/pkg/ai"
	"aftersec/pkg/binaryauth"
	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/devicecontrol"
	"aftersec/pkg/dnsanalytics"
	"aftersec/pkg/edr"
	"aftersec/pkg/fim"
	"aftersec/pkg/forensics"
	"aftersec/pkg/netsensor"
	"aftersec/pkg/plugins"
	"aftersec/pkg/ransomware"
	"aftersec/pkg/selfprotect"
	"aftersec/pkg/tuning"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const banner = `
    ___    ______ __   ______ ____   _____   ______  ______
   /   |  / ____// /_ / ____// __ \ / ___/  / ____/ / ____/
  / /| | / /__  / __// __/  / /_/ / \__ \  / __/   / /     
 / ___ |/ /___ / /_ / /___ / _, _/ ___/ / / /___  / /___   
/_/  |_|\____/ \__/ \____//_/ |_| /____/ /_____/  \____/   
                                                           
`

// forensicsWorker permanently drains the mountQueue, limiting system load to 1 concurrent sweep per thread
func forensicsWorker(ctx context.Context, id int, mgr storage.Manager, queue <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case mountPath := <-queue:
			log.Printf("[Worker #%d] 🔍 Processing Intercepted Mount: %s", id, mountPath)
			// Wait momentarily to ensure macOS finishes populating the volume contents
			time.Sleep(3 * time.Second)

			// Absolute 30-second killswitch on this specific volume scan
			scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

			err := filepath.Walk(mountPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || scanCtx.Err() != nil {
					return nil
				}

				if info.IsDir() && filepath.Ext(path) == ".app" {
					log.Printf("[Worker #%d] 🛡️ Validating Cryptographic Seal: %s", id, path)
					res, _ := forensics.VerifyMacBundle(scanCtx, path)
					if res != nil && !res.IsValid {
						payload, _ := json.Marshal(map[string]interface{}{"container": path, "issues": res.Issues})
						mgr.LogTelemetryEvent("container_forensics", "broken_signature", "critical", string(payload))
						log.Printf("❌ CRITICAL: Cryptographic seal broken on App Bundle: %s", path)
					}
					return filepath.SkipDir
				}

				if !info.IsDir() && filepath.Ext(path) == ".pkg" {
					log.Printf("[Worker #%d] 📦 Bursting Sandbox for PKG: %s", id, path)
					res, _ := forensics.AnalyzeInstaller(scanCtx, path)
					if res != nil && res.RawScriptsExtracted > 0 {
						payload, _ := json.Marshal(map[string]interface{}{"container": path, "count": res.RawScriptsExtracted})
						mgr.LogTelemetryEvent("container_forensics", "root_scripts_detected", "high", string(payload))
						log.Printf("⚠️ WARNING: Detected embedded root execution scripts inside payload: %s", path)
					}
				}
				return nil
			})
			cancel() // Free context resources

			if err != nil {
				log.Printf("[Worker #%d] ❌ Volume Forensics Failed: %v", id, err)
			}
		}
	}
}

func handleAuthEvent(event edr.ProcessEvent, consumer *edr.ESConsumer, cfg *client.ClientConfig, mgr storage.Manager, authorizer *binaryauth.Authorizer, dsClient interface {
	RealTimeScan(ctx context.Context, path string, timeoutSeconds int) (bool, darkscan.ThreatLevel, error)
	IsEnabled() bool
}) {
	allow := true
	defer func() {
		if err := consumer.RespondAuth(event, allow, true); err != nil {
			log.Printf("Failed to respond to AUTH_EXEC for %s: %v", event.ExecPath, err)
		}
	}()

	if cfg.Daemon.BinaryAuth.Enabled {
		identity, inspectErr := binaryauth.InspectExecutable(event.ExecPath)
		if inspectErr != nil {
			allow = false
			log.Printf("🛑 [BINARY AUTH] Identity collection failed for %s: %v", event.ExecPath, inspectErr)
			return
		}
		decision, authErr := authorizer.Authorize(identity)
		record, _ := json.Marshal(map[string]any{
			"path": event.ExecPath, "identity": identity, "decision": decision,
		})
		severity := "info"
		if decision == binaryauth.DecisionDeny || authErr != nil {
			severity = "critical"
		}
		if err := mgr.LogTelemetryEvent("binary_authorization", string(decision), severity, string(record)); err != nil {
			allow = false
			log.Printf("🛑 [BINARY AUTH] Decision audit failed for %s: %v", event.ExecPath, err)
			return
		}
		if decision == binaryauth.DecisionDeny || authErr != nil {
			allow = false
			log.Printf("🛑 [BINARY AUTH] Blocked execution: %s", event.ExecPath)
			return
		}
	}

	// Phase 1: Local YARA Sandboxing
	isMalicious, err := plugins.ScanYara(mgr, event.ExecPath)
	if err == nil && isMalicious {
		allow = false
		log.Printf("🛑 [LOCAL YARA ENGINE] Blocked execution: %s", event.ExecPath)
		return // Skip cloud detonation, already convicted
	}

	// Phase 1.5: DarkScan Multi-Engine Real-Time Protection
	if dsClient != nil && dsClient.IsEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		shouldBlock, threatLevel, err := dsClient.RealTimeScan(ctx, event.ExecPath, 10)
		if err != nil {
			allow = false
			log.Printf("🛑 [DARKSCAN] Scan error; blocked execution of %s: %v", event.ExecPath, err)
			return
		} else if shouldBlock {
			allow = false
			log.Printf("🛑 [DARKSCAN] Blocked execution: %s (Threat Level: %s)", event.ExecPath, threatLevel)
			mgr.LogTelemetryEvent("darkscan", "blocked_execution", "critical", fmt.Sprintf(`{"path": "%s", "threat_level": "%s"}`, event.ExecPath, threatLevel))

			// Deploy local immunity
			go func(path string) {
				if err := plugins.GenerateImmunitySignature(path, "DarkScan Edge Conviction"); err != nil {
					log.Printf("⚠️ [IMMUNITY ENGINE] Failed to compile rule for %s: %v", path, err)
				}
			}(event.ExecPath)
			return
		} else if threatLevel > darkscan.ThreatLevelNone {
			log.Printf("⚠️ [DARKSCAN] Suspicious file allowed: %s (Threat Level: %s)", event.ExecPath, threatLevel)
			mgr.LogTelemetryEvent("darkscan", "suspicious_allowed", "high", fmt.Sprintf(`{"path": "%s", "threat_level": "%s"}`, event.ExecPath, threatLevel))
		}
	}

	// Phase 2: Cloud Detonation Engine (enterprise enforcement only).
	if cfg.Server == nil || cfg.Server.Address == "" || cfg.Mode != client.ModeEnterprise {
		return
	}

	f, err := os.Open(event.ExecPath)
	if err != nil {
		allow = false
		log.Printf("[AUTH_EXEC] Failed to read binary %s: %v", event.ExecPath, err)
		return
	}
	defer f.Close()

	urlStr := fmt.Sprintf("%s/api/v1/detonate", cfg.Server.Address)
	req, err := http.NewRequest("POST", urlStr, f)
	if err != nil {
		allow = false
		log.Printf("[AUTH_EXEC] Failed to construct detonation request for %s: %v", event.ExecPath, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Server.EnrollmentToken)

	// ESF imposes a 60s max stall; we time out slightly earlier to allow fallback
	httpClient := &http.Client{Timeout: 45 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		allow = false
		log.Printf("🛑 [DETONATION] Server unreachable; blocked execution of %s: %v", event.ExecPath, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		allow = false
		log.Printf("🛑 [DETONATION] Server returned %d; blocked execution of %s", resp.StatusCode, event.ExecPath)
		return
	}

	var result struct {
		Verdict string `json:"verdict"`
		Score   int    `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if result.Verdict == "DENY" {
			allow = false
			log.Printf("🛑 [DETONATION] SERVER BLOCKED EXECUTION: %s (Score: %d)", event.ExecPath, result.Score)

			// Deploy local immunity so we don't query the cloud for this exact structural family again
			go func(path string, score int) {
				reason := fmt.Sprintf("Cloud AI Detonation Conviction (Score: %d)", score)
				if err := plugins.GenerateImmunitySignature(path, reason); err != nil {
					log.Printf("⚠️ [IMMUNITY ENGINE] Failed to compile rule for %s: %v", path, err)
				}
			}(event.ExecPath, result.Score)
		} else {
			log.Printf("✅ [DETONATION] Server Allowed Execution: %s", event.ExecPath)
		}
	} else {
		allow = false
		log.Printf("🛑 [DETONATION] Invalid verdict response; blocked execution of %s: %v", event.ExecPath, err)
	}
}

func main() {
	// Matrix CLI Interface Logo
	fmt.Printf("\033[36m%s\033[0m\n", banner)
	fmt.Println("\033[32m[OK]\033[0m Initializing AfterSec Core Daemon...")

	// EDR Sensor Initialization
	edrEvents := make(chan edr.ProcessEvent, 100)
	var edrStartupErr error
	esConsumer, err := edr.NewESConsumer(edrEvents)
	if err != nil {
		edrStartupErr = err
		fmt.Printf("\033[33m[WARN]\033[0m Endpoint Security Sensor Standby (Requires Root & Code Entitlements): %v\n", err)
	} else {
		// 0=AUTH_EXEC, 24=NOTIFY_EXEC, 26=NOTIFY_EXIT, 123=NOTIFY_MOUNT
		fmt.Printf("\033[32m[OK]\033[0m Endpoint Security Framework Driver Active. Subscribed: AUTH_EXEC, NOTIFY_EXEC, NOTIFY_EXIT...\n")
		err = esConsumer.Subscribe([]uint32{0, 24, 26, 123, edr.NotifyWriteEventCode(), edr.AuthWriteEventCode()})
		if err != nil {
			edrStartupErr = err
			log.Printf("Failed to subscribe to ES events: %v", err)
		}
	}

	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".aftersec", "config.yaml")

	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		log.Printf("Warning: failed to load config (%v), falling back to default standalone config", err)
		cfg = client.DefaultClientConfig()
	}
	if edrStartupErr != nil &&
		(cfg.Daemon.SelfProtection.Required || cfg.Daemon.Ransomware.Required ||
			cfg.Daemon.BinaryAuth.Required) {
		log.Fatalf("required native endpoint authorization unavailable: %v", edrStartupErr)
	}

	tamperGuard := selfprotect.NewGuard(cfg.Daemon.SelfProtection.ProtectedPaths)
	if cfg.Daemon.SelfProtection.Enabled {
		if err := selfprotect.WritePIDFile(cfg.Daemon.SelfProtection.PIDFile); err != nil {
			if cfg.Daemon.SelfProtection.Required {
				log.Fatalf("required watchdog PID file unavailable: %v", err)
			}
			log.Printf("watchdog PID file unavailable: %v", err)
		} else {
			defer os.Remove(cfg.Daemon.SelfProtection.PIDFile)
		}
		nativeGuard, guardErr := selfprotect.StartNativeGuard(
			cfg.Daemon.SelfProtection.ProtectedPaths,
			cfg.Daemon.SelfProtection.BPFObjectPath,
		)
		if guardErr != nil {
			if cfg.Daemon.SelfProtection.Required {
				log.Fatalf("required native self-protection unavailable: %v", guardErr)
			}
			log.Printf("native self-protection unavailable: %v", guardErr)
		} else if nativeGuard != nil {
			defer nativeGuard.Close()
		}
	}

	// Apply Enterprise Fleet Resource Constraints
	if cfg.Daemon.Resources.MaxWorkers > 0 {
		runtime.GOMAXPROCS(cfg.Daemon.Resources.MaxWorkers)
		fmt.Printf("\033[36m[TUNING]\033[0m OS Thread pool ceiling strictly capped to %d active cores.\n", cfg.Daemon.Resources.MaxWorkers)
	}

	if err := tuning.SetProcessPriority(cfg.Daemon.Resources.Priority); err != nil {
		fmt.Printf("\033[33m[WARN]\033[0m Could not bind process priority (%s): %v\n", cfg.Daemon.Resources.Priority, err)
	} else {
		fmt.Printf("\033[36m[TUNING]\033[0m Kernel process scheduler heavily bound: '%s'.\n", cfg.Daemon.Resources.Priority)
	}

	// AI Analyst Initialization
	if err := ai.InitGenkit(context.Background(), cfg); err != nil {
		fmt.Printf("\033[33m[WARN]\033[0m Genkit AI Hub Standby (Missing API_KEY block): %v\n", err)
	} else {
		fmt.Printf("\033[32m[OK]\033[0m Genkit AI Tri-Model Hub Initialized (%s)\n", cfg.Daemon.AI.Provider)
	}

	// Behavior Intent Graph Initialization
	ig := forensics.NewIntentGraph()
	if err := ig.StartSensor(context.Background()); err != nil {
		fmt.Printf("\033[33m[WARN]\033[0m Intent Sensor failed to start: %v\n", err)
	} else {
		fmt.Printf("\033[32m[OK]\033[0m AI Intent Graph & Behavioral Triage Active\n")
	}

	var mgr storage.Manager
	if cfg.Mode == client.ModeEnterprise {
		if cfg.Server == nil {
			log.Fatalf("Enterprise mode configured but server config is missing")
		}
		mgr, err = storage.NewCacheManager(cfg)
		if err != nil {
			log.Fatalf("failed to init enterprise cache storage: %v", err)
		}
		log.Printf("Initialized in ENTERPRISE mode connected to %s", cfg.Server.Address)
	} else {
		mgr, err = storage.NewSQLiteManager(cfg.Storage.Path)
		if err != nil {
			log.Fatalf("failed to init local storage: %v", err)
		}
		log.Printf("Initialized in STANDALONE mode")
	}

	var binaryAuthorizer *binaryauth.Authorizer
	if cfg.Daemon.BinaryAuth.Enabled {
		var publicKey ed25519.PublicKey
		if cfg.Daemon.BinaryAuth.PublicKeyBase64 != "" {
			decoded, decodeErr := base64.StdEncoding.DecodeString(cfg.Daemon.BinaryAuth.PublicKeyBase64)
			if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
				log.Fatalf("invalid binary authorization public key")
			}
			publicKey = ed25519.PublicKey(decoded)
		}
		binaryAuthorizer = binaryauth.NewAuthorizer(publicKey, time.Now)
		if cfg.Daemon.BinaryAuth.PublicKeyBase64 != "" {
			policy, loadErr := binaryauth.LoadPolicy(cfg.Daemon.BinaryAuth.PolicyCachePath)
			if loadErr == nil {
				loadErr = binaryAuthorizer.Activate(policy)
			}
			if loadErr != nil {
				if cfg.Daemon.BinaryAuth.Required {
					log.Fatalf("required binary authorization policy unavailable: %v", loadErr)
				}
				log.Printf("binary authorization running in audited learn mode: %v", loadErr)
			}
		}
	}

	var ransomwareShield *ransomware.Shield
	var ransomwareCanaries *ransomware.CanaryManager
	if cfg.Daemon.Ransomware.Enabled {
		for _, directory := range cfg.Daemon.Ransomware.CanaryDirectories {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				if cfg.Daemon.Ransomware.Required {
					log.Fatalf("required ransomware canary directory unavailable: %v", err)
				}
				log.Printf("ransomware shield disabled: %v", err)
				continue
			}
		}
		ransomwareCanaries = ransomware.NewCanaryManager(cfg.Daemon.Ransomware.CanaryDirectories)
		if _, err := ransomwareCanaries.Plant(); err != nil {
			if cfg.Daemon.Ransomware.Required {
				log.Fatalf("required ransomware canaries unavailable: %v", err)
			}
			log.Printf("ransomware shield disabled: %v", err)
			ransomwareCanaries = nil
		} else {
			ransomwareShield = ransomware.NewShield(
				ransomware.ProcessSuspender{},
				ransomwareTelemetryRecorder{logger: mgr},
				ransomware.Policy{
					RenameBurst:      cfg.Daemon.Ransomware.RenameBurst,
					EntropyThreshold: cfg.Daemon.Ransomware.EntropyThreshold,
				},
			)
		}
	}

	if cfg.Daemon.DeviceControl.Enabled {
		allowed := make(map[devicecontrol.DeviceID]devicecontrol.Access, len(cfg.Daemon.DeviceControl.Allowed))
		for id, access := range cfg.Daemon.DeviceControl.Allowed {
			allowed[devicecontrol.DeviceID(id)] = devicecontrol.Access(access)
		}
		controller := devicecontrol.NewController(devicecontrol.Policy{
			Mode: devicecontrol.Mode(cfg.Daemon.DeviceControl.Mode), Allowed: allowed,
		}, devicecontrol.NewPlatformMounter())
		source := devicecontrol.NewPlatformSource()
		deviceCtx, cancelDevices := context.WithCancel(context.Background())
		defer cancelDevices()
		go func() {
			if err := controller.Run(deviceCtx, source, deviceDecisionRecorder{logger: mgr}); err != nil &&
				err != context.Canceled {
				if cfg.Daemon.DeviceControl.Required {
					log.Fatalf("required removable-device control stopped: %v", err)
				}
				log.Printf("removable-device control stopped: %v", err)
			}
		}()
	}

	if cfg.Daemon.NetworkSensor.Enabled {
		backend, backendErr := netsensor.NewPlatformBackend(
			cfg.Daemon.NetworkSensor.EventPath,
			cfg.Daemon.NetworkSensor.BPFObjectPath,
		)
		if backendErr != nil {
			if cfg.Daemon.NetworkSensor.Required {
				log.Fatalf("required process-attributed network sensor unavailable: %v", backendErr)
			}
			log.Printf("network sensor disabled: %v", backendErr)
		} else {
			flowCtx, cancelFlows := context.WithCancel(context.Background())
			defer cancelFlows()
			flows := make(chan netsensor.Flow, 256)
			sensor := netsensor.New(backend, cfg.Daemon.NetworkSensor.Required)
			sensorErrors := make(chan error, 2)
			go func() {
				err := sensor.Run(flowCtx, flows)
				close(flows)
				sensorErrors <- err
			}()
			go func() {
				sensorErrors <- persistNetworkFlows(flowCtx, flows, mgr)
			}()
			go func() {
				for range 2 {
					if sensorErr := <-sensorErrors; sensorErr != nil && sensorErr != context.Canceled {
						cancelFlows()
						if cfg.Daemon.NetworkSensor.Required {
							log.Fatalf("required network telemetry pipeline stopped: %v", sensorErr)
						}
						log.Printf("network telemetry pipeline stopped: %v", sensorErr)
						return
					}
				}
			}()
			log.Printf("Process-attributed network sensor active: %s", cfg.Daemon.NetworkSensor.EventPath)
		}
	}

	dnsCorrelator := dnsanalytics.NewCorrelator(5*time.Minute, 4096)
	if cfg.Daemon.DNSSensor.Enabled {
		source, sourceErr := dnsanalytics.NewPlatformSource(
			cfg.Daemon.DNSSensor.EventPath,
			cfg.Daemon.DNSSensor.BPFObjectPath,
		)
		if sourceErr != nil {
			if cfg.Daemon.DNSSensor.Required {
				log.Fatalf("required process-attributed DNS sensor unavailable: %v", sourceErr)
			}
			log.Printf("DNS sensor disabled: %v", sourceErr)
		} else {
			dnsCtx, cancelDNS := context.WithCancel(context.Background())
			defer cancelDNS()
			queries := make(chan dnsanalytics.Query, 256)
			capture := dnsanalytics.NewCapture(cfg.Daemon.DNSSensor.Required)
			detector := dnsanalytics.NewDetector(nil, dnsanalytics.Policy{
				DGAScoreThreshold: cfg.Daemon.DNSSensor.DGAThreshold,
			})
			dnsErrors := make(chan error, 2)
			go func() {
				err := capture.Start(dnsCtx, source, func(query dnsanalytics.Query) error {
					select {
					case <-dnsCtx.Done():
						return dnsCtx.Err()
					case queries <- query:
						return nil
					}
				})
				close(queries)
				dnsErrors <- err
			}()
			go func() {
				dnsErrors <- persistDNSQueries(dnsCtx, queries, detector, dnsCorrelator, mgr)
			}()
			go func() {
				for range 2 {
					if dnsErr := <-dnsErrors; dnsErr != nil && dnsErr != context.Canceled {
						cancelDNS()
						if cfg.Daemon.DNSSensor.Required {
							log.Fatalf("required DNS telemetry pipeline stopped: %v", dnsErr)
						}
						log.Printf("DNS telemetry pipeline stopped: %v", dnsErr)
						return
					}
				}
			}()
			log.Printf("Process-attributed DNS sensor active")
		}
	}

	// Initialize the buffered mount queue (Max 100 queued events before we shed load)
	mountQueue := make(chan string, 100)

	// Provision 2 dedicated Forensics Workers (Locks CPU overhead explicitly)
	forensicsCtx, forensicsCancel := context.WithCancel(context.Background())
	defer forensicsCancel()
	for i := 1; i <= 2; i++ {
		go forensicsWorker(forensicsCtx, i, mgr, mountQueue)
	}

	// Bounded semaphore for AUTH_EXEC goroutines — prevents goroutine explosion under load
	authExecSem := make(chan struct{}, 32)

	// Initialize DarkScan client for real-time malware detection
	var dsClient interface {
		RealTimeScan(ctx context.Context, path string, timeoutSeconds int) (bool, darkscan.ThreatLevel, error)
		ScanWithReport(ctx context.Context, path string) (*darkscan.IntegrationReport, error)
		UpdateEngines(ctx context.Context) error
		UpdateRules(ctx context.Context) error
		ScanBrowserPrivacy(ctx context.Context, browsers []string) ([]*darkscan.PrivacyScanResult, error)
		PruneHashStore(ctx context.Context, olderThan time.Duration) (int, error)
		CleanQuarantine(ctx context.Context, olderThan time.Duration) (int, error)
		IsEnabled() bool
		GetEngineCount() int
	}
	if cfg.Daemon.DarkScan.Enabled {
		var err error
		if cfg.Daemon.DarkScan.UseCLI {
			dsClient, err = darkscan.NewCLIClient(&cfg.Daemon.DarkScan, cfg.Daemon.DarkScan.CLIBinaryPath)
		} else {
			dsClient, err = darkscan.NewClient(&cfg.Daemon.DarkScan)
		}
		if err != nil {
			fmt.Printf("\033[33m[WARN]\033[0m DarkScan initialization failed: %v\n", err)
		} else {
			fmt.Printf("\033[32m[OK]\033[0m DarkScan Multi-Engine Protection Active (%d engines)\n", dsClient.GetEngineCount())

			// Start API Server if Enabled
			if cfg.Daemon.DarkScan.APIEnabled {
				go startDarkScanAPI(context.Background(), cfg, dsClient)
			}

			// Start Auto Updates
			if cfg.Daemon.DarkScan.Engines.ClamAV.AutoUpdate {
				darkscan.StartAutoUpdater(context.Background(), dsClient, 6*time.Hour)
			}
		}
	}

	// Process ESF events and stream into SQLite
	fimMonitor := fim.NewMonitor([]string{"/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents"}, 1<<20)
	fimEvidence := fim.NewEvidenceCapture(1<<20, 4096)
	if esConsumer != nil {
		go func() {
			for event := range edrEvents {
				if event.Type == edr.EventAuthWrite {
					allow := true
					if err := fimMonitor.ValidateEvent(fim.Event{
						Path: event.ExecPath, WriterPID: event.PID,
					}); err == nil {
						if err := fimEvidence.Begin(event.PID, event.ExecPath); err != nil {
							log.Printf("FIM before-write evidence failed for %s: %v", event.ExecPath, err)
							allow = false
						}
					}
					if ransomwareShield != nil && ransomwareCanaries != nil &&
						ransomwareCanaries.IsCanary(event.ExecPath) {
						if err := ransomwareShield.Observe(context.Background(), ransomware.Event{
							PID: event.PID, Path: event.ExecPath, Canary: true,
						}); err != nil {
							log.Printf("Ransomware containment failed for %s: %v", event.ExecPath, err)
						}
						allow = false
					}
					if cfg.Daemon.SelfProtection.Enabled {
						resolved, resolveErr := filepath.EvalSymlinks(event.ExecPath)
						if resolveErr != nil {
							resolved = event.ExecPath
						}
						selfPath, _ := os.Executable()
						selfPath, _ = filepath.EvalSymlinks(selfPath)
						signerTrusted := event.ActorPath != "" && event.ActorPath == selfPath
						if tamperGuard.AuthorizeResolvedMutation(event.ExecPath, resolved, signerTrusted) != nil {
							allow = false
						}
					}
					if err := esConsumer.RespondAuth(event, allow, false); err != nil {
						log.Printf("Failed to respond to AUTH_WRITE for %s: %v", event.ExecPath, err)
					}
					if !allow {
						fimEvidence.Cancel(event.PID, event.ExecPath)
					}
					severity := "info"
					if !allow {
						severity = "critical"
					}
					b, _ := json.Marshal(event)
					mgr.LogTelemetryEvent("self_protection", "agent_mutation", severity, string(b))
					continue
				}
				if event.Type == edr.EventNotifyOpen {
					if err := fimMonitor.ValidateEvent(fim.Event{
						Path: event.ExecPath, WriterPID: event.PID,
					}); err == nil {
						if err := fimEvidence.Begin(event.PID, event.ExecPath); err != nil {
							log.Printf("FIM open evidence failed for %s: %v", event.ExecPath, err)
						}
					}
					if ransomwareShield != nil && ransomwareCanaries != nil &&
						ransomwareCanaries.IsCanary(event.ExecPath) {
						if err := ransomwareShield.Observe(context.Background(), ransomware.Event{
							PID: event.PID, Path: event.ExecPath, Canary: true,
						}); err != nil {
							log.Printf("Ransomware containment failed for %s: %v", event.ExecPath, err)
						}
					}
				}
				if event.Type == edr.EventNotifyClose {
					fimEvidence.Cancel(event.PID, event.ExecPath)
				}
				if event.Type == edr.EventAuthExec {
					select {
					case authExecSem <- struct{}{}:
						go func(ev edr.ProcessEvent) {
							defer func() { <-authExecSem }()
							handleAuthEvent(ev, esConsumer, cfg, mgr, binaryAuthorizer, dsClient)
						}(event)
					default:
						log.Printf("🛑 [LOAD SHEDDING] AUTH_EXEC queue full; blocking %s", event.ExecPath)
						if err := esConsumer.RespondAuth(event, false, true); err != nil {
							log.Printf("Failed to respond to AUTH_EXEC for %s: %v", event.ExecPath, err)
						}
					}
					continue
				}

				b, _ := json.Marshal(event)
				mgr.LogTelemetryEvent("endpoint_security", string(event.Type), "info", string(b))
				if event.Type == edr.EventNotifyWrite {
					if err := fimMonitor.ValidateEvent(fim.Event{
						Path: event.ExecPath, WriterPID: event.PID,
					}); err == nil {
						evidence, evidenceErr := fimEvidence.Complete(event.PID, event.ExecPath)
						if evidenceErr != nil {
							log.Printf("🛑 [FIM] missing native evidence for %s: %v", event.ExecPath, evidenceErr)
							continue
						}
						if err := fimMonitor.ValidateEvent(evidence); err != nil {
							log.Printf("🛑 [FIM] rejected write event for %s: %v", event.ExecPath, err)
							continue
						}
						evidenceJSON, _ := json.Marshal(evidence)
						mgr.LogTelemetryEvent("file_integrity", "critical_path_write", "high", string(evidenceJSON))
						if detection, err := dnsCorrelator.RecordPersistence(dnsanalytics.PersistenceObservation{
							PID: event.PID, Path: event.ExecPath, At: event.Timestamp,
						}); err != nil {
							log.Printf("DNS/persistence correlation failed: %v", err)
						} else if detection != nil {
							detectionJSON, _ := json.Marshal(detection)
							mgr.LogTelemetryEvent("dns_correlator", "dga_with_persistence", "critical", string(detectionJSON))
						}
					}
				}

				// Do not spam stdout for high-volume kernel bursts natively
				if event.Type != edr.EventNotifyExec && event.Type != edr.EventNotifyExit {
					log.Printf("📥 [ESF -> SQLite] Logged %s: %s (PID: %d)", event.Type, event.ExecPath, event.PID)
				}

				// Autonomous DMG/ISO Container Forensics Load Shedding
				if event.Type == edr.EventNotifyMount && event.MountPath != "" {
					select {
					case mountQueue <- event.MountPath:
						log.Printf("🚨 [KERNEL INTERCEPT] Enqueued Volume: %s", event.MountPath)
					default:
						// DOS protection active: Queue is physically full. Drop the event gracefully.
						log.Printf("🔥 [LOAD SHEDDING DEPLOYED] Discarding NOTIFY_MOUNT event for %s. Forensics workers saturated (>100 events).", event.MountPath)
					}
				}
			}
		}()
	}

	// AI Telemetry Rolling Window Auto-Pruner (4-Hour Max)
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			pruned, err := mgr.PruneTelemetry(4)
			if err != nil {
				log.Printf("Error pruning old SQLite telemetry: %v", err)
			} else if pruned > 0 {
				log.Printf("🧹 Pruned %d stale telemetry rows to maintain 4-hour rolling window.", pruned)
			}
		}
	}()

	// DarkScan Background Workers
	if dsClient != nil && dsClient.IsEnabled() {
		// YARA Rule Auto-Updater
		if cfg.Daemon.DarkScan.RuleManager.Enabled && cfg.Daemon.DarkScan.RuleManager.AutoUpdate {
			interval := 6 * time.Hour // Default
			if cfg.Daemon.DarkScan.RuleManager.UpdateInterval != "" {
				if parsed, err := time.ParseDuration(cfg.Daemon.DarkScan.RuleManager.UpdateInterval); err == nil {
					interval = parsed
				}
			}
			log.Printf("🛡️  [DARKSCAN] Starting YARA rule auto-updater (interval: %v)", interval)
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for range ticker.C {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
					if err := dsClient.UpdateRules(ctx); err != nil {
						log.Printf("⚠️  [DARKSCAN] Rule update failed: %v", err)
					} else {
						log.Printf("✅ [DARKSCAN] Rules updated successfully")
					}
					cancel()
				}
			}()
		}

		// Privacy Auto-Scanner
		if cfg.Daemon.DarkScan.Privacy.Enabled && cfg.Daemon.DarkScan.Privacy.AutoScanInterval != "" {
			interval, err := time.ParseDuration(cfg.Daemon.DarkScan.Privacy.AutoScanInterval)
			if err == nil && interval > 0 {
				log.Printf("🕵️  [DARKSCAN] Starting privacy auto-scanner (interval: %v)", interval)
				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for range ticker.C {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						browsers := cfg.Daemon.DarkScan.Privacy.ScanBrowsers
						if len(browsers) == 0 {
							browsers = []string{"chrome", "firefox", "safari"}
						}
						results, err := dsClient.ScanBrowserPrivacy(ctx, browsers)
						if err != nil {
							log.Printf("⚠️  [DARKSCAN] Privacy scan failed: %v", err)
						} else {
							totalTrackers := 0
							for _, result := range results {
								totalTrackers += len(result.TrackersFound)
							}
							if totalTrackers > 0 {
								log.Printf("🕵️  [DARKSCAN] Privacy scan found %d trackers across %d browsers", totalTrackers, len(results))
							}
						}
						cancel()
					}
				}()
			}
		}

		// Hash Store Pruning (Daily)
		if cfg.Daemon.DarkScan.HashStore.Enabled {
			retentionDays := cfg.Daemon.DarkScan.HashStore.RetentionDays
			if retentionDays == 0 {
				retentionDays = 90 // Default
			}
			log.Printf("🗄️  [DARKSCAN] Starting hash store pruner (retention: %d days)", retentionDays)
			go func() {
				ticker := time.NewTicker(24 * time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					olderThan := time.Duration(retentionDays) * 24 * time.Hour
					pruned, err := dsClient.PruneHashStore(ctx, olderThan)
					if err != nil {
						log.Printf("⚠️  [DARKSCAN] Hash store pruning failed: %v", err)
					} else if pruned > 0 {
						log.Printf("🗄️  [DARKSCAN] Pruned %d old hash entries", pruned)
					}
					cancel()
				}
			}()
		}

		// Quarantine Cleanup (Daily)
		if cfg.Daemon.DarkScan.Quarantine.Enabled && cfg.Daemon.DarkScan.Quarantine.AutoDeleteDays > 0 {
			autoDeleteDays := cfg.Daemon.DarkScan.Quarantine.AutoDeleteDays
			log.Printf("🗑️  [DARKSCAN] Starting quarantine auto-cleanup (retention: %d days)", autoDeleteDays)
			go func() {
				ticker := time.NewTicker(24 * time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					olderThan := time.Duration(autoDeleteDays) * 24 * time.Hour
					cleaned, err := dsClient.CleanQuarantine(ctx, olderThan)
					if err != nil {
						log.Printf("⚠️  [DARKSCAN] Quarantine cleanup failed: %v", err)
					} else if cleaned > 0 {
						log.Printf("🗑️  [DARKSCAN] Cleaned %d old quarantine entries", cleaned)
					}
					cancel()
				}
			}()
		}
	}

	if cfg.Mode == client.ModeEnterprise {
		modes.RunEnterprise(cfg, mgr)
	} else {
		modes.RunStandalone(cfg, mgr)
	}
}
