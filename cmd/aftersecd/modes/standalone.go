package modes

import (
	"aftersec/pkg/ai"
	"aftersec/pkg/api"
	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"aftersec/pkg/edr"
	"aftersec/pkg/forensics"
	"aftersec/pkg/scanners"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func isQuietHour(cfg *client.ClientConfig) bool {
	if !cfg.Daemon.Scheduling.QuietHoursEnabled {
		return false
	}
	start, err1 := time.Parse("15:04", cfg.Daemon.Scheduling.QuietHoursStart)
	end, err2 := time.Parse("15:04", cfg.Daemon.Scheduling.QuietHoursEnd)
	if err1 != nil || err2 != nil {
		return false
	}
	now := time.Now()
	nowMinutes := now.Hour()*60 + now.Minute()
	startMinutes := start.Hour()*60 + start.Minute()
	endMinutes := end.Hour()*60 + end.Minute()
	
	if startMinutes <= endMinutes {
		return nowMinutes >= startMinutes && nowMinutes <= endMinutes
	}
	return nowMinutes >= startMinutes || nowMinutes <= endMinutes
}

// RunStandalone starts the daemon in standalone mode
func RunStandalone(cfg *client.ClientConfig, mgr storage.Manager) {
	log.Println("Starting AfterSec daemon in Standalone Mode")

	go func() {
		if err := api.StartServer(8080, mgr); err != nil {
			log.Fatalf("API server failed: %v", err)
		}
	}()
	
	alertChan := make(chan forensics.SyscallAlert, 100)
	go func() {
		log.Println("Starting continuous syscall monitoring via dtrace...")
		if err := forensics.StartSyscallMonitor(alertChan); err != nil {
			log.Printf("dtrace monitor stopped or failed: %v", err)
		}
	}()

	go func() {
		f, err := os.OpenFile("/var/log/aftersecd-alerts.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("could not open alerts log: %v", err)
			f = os.Stdout
		}
		defer func() {
			if f != os.Stdout {
				f.Close()
			}
		}()

		for alert := range alertChan {
			if alert.Score.String() == "CRITICAL" && !cfg.Daemon.Alerts.AlertOnCritical {
				continue
			}
			if alert.Score.String() == "HIGH" && !cfg.Daemon.Alerts.AlertOnHigh {
				continue
			}
			msg := fmt.Sprintf("[%s] SYSTEM ALERT | PID: %d | CMD: %s | PATTERN: %s | SEVERITY: %s\n", 
				alert.Timestamp.Format(time.RFC3339), alert.PID, alert.Command, alert.Pattern, alert.Score)
			log.Print(msg)
			if f != os.Stdout {
				f.WriteString(msg)
			}

			// AI Analysis for high/critical behavioral alerts
			if alert.Score.String() == "HIGH" || alert.Score.String() == "CRITICAL" {
				log.Println("🤖 [AI Analyst] Analyzing high-severity process pattern...")
				analysis, err := ai.AnalyzeThreat(context.Background(), msg)
				if err == nil {
					log.Printf("🤖 \033[36m[AI Analysis Result]:\n%s\033[0m\n", analysis)
					
					// Fire macOS Desktop Alert via AppleScript
					appleScript := `display notification "AI Flagged a High-Severity Process Anomaly" with title "AfterSec EDR" subtitle "Critical Alert" sound name "Basso"`
					_ = exec.Command("osascript", "-e", appleScript).Run()
				}
			}
		}
	}()

	// Unified Logging Stream (Authd & TCC Privacy)
	logContext, logCancel := context.WithCancel(context.Background())
	defer logCancel()
	
	logAlerts := make(chan edr.LogEvent, 100)
	go func() {
		fmt.Println("\033[36m[OK]\033[0m Starting macOS Unified Logging stream (TCC Sandbox, Authd)...")
		if err := edr.StartUnifiedLogMonitor(logContext, logAlerts); err != nil {
			log.Printf("\033[33m[WARN]\033[0m Unified Logging stream failed: %v", err)
		}
	}()

	go func() {
		for event := range logAlerts {
			msg := fmt.Sprintf("[\033[33mUNIFIED LOG\033[0m] %s | Subsystem: %s | Process: %s | Message: %s\n", 
				event.Timestamp, event.Subsystem, event.ProcessImage, event.EventMessage)
			// Print routine Unified Log captures
			fmt.Print(msg)
			
			// Let's pass Auth failures or TCC prompts selectively to Genkit
			lowerMsg := strings.ToLower(event.EventMessage)
			if strings.Contains(lowerMsg, "denied") || strings.Contains(lowerMsg, "failed") || strings.Contains(lowerMsg, "unauthorized") {
				log.Println("🤖 [AI Analyst] Intercepted Critical Log Event. Analyzing...")
				analysis, _ := ai.AnalyzeThreat(context.Background(), msg)
				if analysis != "" {
					fmt.Printf("🤖 \033[36m[AI Result]:\n%s\033[0m\n", analysis)
					appleScript := `display notification "AI Flagged Syslog Anomaly" with title "AfterSec Logging" subtitle "Critical Alert" sound name "Basso"`
					_ = exec.Command("osascript", "-e", appleScript).Run()
				}
			}
		}
	}()

	interval, err := time.ParseDuration(cfg.Daemon.Scheduling.ScanInterval)
	if err != nil || interval <= 0 {
		log.Printf("invalid scan_interval %s, defaulting to 6h", cfg.Daemon.Scheduling.ScanInterval)
		interval = 6 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runScan := func() {
		if isQuietHour(cfg) {
			log.Printf("[%s] skipping scan due to quiet hours configuration", time.Now().Format(time.RFC3339))
			return
		}
		
		if cfg.Daemon.Scheduling.Adaptive {
			// Stub: Here we would check system load and backoff if max_cpu_percent is exceeded
			log.Printf("[%s] adaptive scheduling active (MaxCPU: %d%%)", time.Now().Format(time.RFC3339), cfg.Daemon.Resources.MaxCPUPercent)
		}

		log.Printf("[%s] running scheduled scan", time.Now().Format(time.RFC3339))
		scanner := scanners.NewMacOSScanner(mgr)

		currentState, err := scanner.Scan(nil)
		if err != nil {
			log.Printf("scan failed: %v", err)
			return
		}

		if ruleBytes, err := os.ReadFile("/etc/aftersec/rules.star"); err == nil {
			log.Println("Evaluating custom Starlark ruleset against baseline...")
			if err := forensics.EvaluateRules(string(ruleBytes), currentState); err != nil {
				log.Printf("Starlark execution failed: %v", err)
			}
		} else if !os.IsNotExist(err) {
			log.Printf("Failed to read generic rules: %v", err)
		}

		latest, _ := mgr.GetLatest()
		if latest != nil {
			diff := core.CompareStates(latest, currentState)
			if diff.HasChanges() {
				log.Println("ALERT: baseline drift detected")
				for _, change := range diff.Changes {
					log.Printf("  %s", change)
				}

				// Generate AI Threat Report for drift
				log.Println("🤖 [AI Analyst] Generating threat analysis for compliance drift...")
				driftJSON := fmt.Sprintf("%v", diff.Changes)
				analysis, err := ai.AnalyzeThreat(context.Background(), driftJSON)
				if err == nil {
					log.Printf("🤖 \033[36m[AI Report]:\n%s\033[0m\n", analysis)
					
					appleScript := `display notification "Baseline Security Drift Detected" with title "AfterSec Compliance" subtitle "Drift Alert" sound name "Ping"`
					_ = exec.Command("osascript", "-e", appleScript).Run()
				} else {
					log.Printf("🤖 \033[33m[AI Warning]: Could not generate report: %v\033[0m", err)
				}
			} else {
				log.Println("no drift detected")
			}
		} else {
			log.Println("establishing initial baseline")
		}

		if err := mgr.SaveCommit(currentState); err != nil {
			log.Printf("failed to save commit: %v", err)
		}
	}

	runScan()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			runScan()
		case sig := <-sigChan:
			log.Printf("received signal %v, shutting down", sig)
			return
		}
	}
}
