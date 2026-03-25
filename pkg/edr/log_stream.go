package edr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
)

// LogEvent represents a structured macOS Unified Log entry.
type LogEvent struct {
	Timestamp      string `json:"timestamp"`
	MachTimestamp  int64  `json:"machTimestamp"`
	MessageType    string `json:"messageType"`
	Category       string `json:"category"`
	Subsystem      string `json:"subsystem"`
	ProcessID      int    `json:"processID"`
	ProcessImage   string `json:"processImagePath"`
	EventMessage   string `json:"eventMessage"`
}

// StartUnifiedLogMonitor starts an asynchronous process that tails the macOS unified log.
// It uses a continuous JSON stream decoder to catch Authentication and Sandbox Privacy violations.
func StartUnifiedLogMonitor(ctx context.Context, alerts chan<- LogEvent) error {
	// Focus specifically on Authentication/Authorization and Application Privacy (TCC)
	predicate := `subsystem == "com.apple.TCC" or subsystem == "com.apple.authd" or subsystem == "com.apple.securityxpc"`
	cmd := exec.CommandContext(ctx, "log", "stream", "--style", "json", "--predicate", predicate)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		defer cmd.Wait()
		decoder := json.NewDecoder(stdout)

		// The Apple log stream begins with an unbounded JSON array `[`
		t, err := decoder.Token()
		if err != nil || fmt.Sprintf("%v", t) != "[" {
			log.Printf("[Warning] Unified Log format failed to initialize properly (expected '[', got %v)", t)
			return
		}

		for decoder.More() {
			var event LogEvent
			if err := decoder.Decode(&event); err == nil {
				// Only emit populated events
				if event.EventMessage != "" {
					select {
					case alerts <- event:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return nil
}
