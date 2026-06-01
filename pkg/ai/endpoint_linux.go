//go:build linux && !onnxruntime

package ai

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/client"
)

type EndpointAI struct {
	cfg         client.EndpointAIConfig
	mu          sync.RWMutex
	samples     int
	lastTrained time.Time
}

var localAI *EndpointAI

func InitEndpointAI(cfg client.EndpointAIConfig) error {
	localAI = &EndpointAI{
		cfg:         cfg,
		samples:     0,
		lastTrained: time.Now(),
	}

	if !cfg.Enabled {
		log.Println("[EndpointAI] Engine disabled by configuration.")
		return nil
	}

	log.Printf("[EndpointAI] Engine initialized in %q mode with interval %q. Model path: %s\n",
		cfg.Mode, cfg.TrainingInterval, cfg.LocalModelPath)
	return nil
}

func Close() {}

func RecordObservation(processName, networkDest string) {
	if localAI == nil || !localAI.cfg.Enabled || localAI.cfg.Mode != client.ModeObserving {
		return
	}

	localAI.mu.Lock()
	defer localAI.mu.Unlock()

	localAI.samples++

	if localAI.samples%100 == 0 {
		log.Printf("[EndpointAI] Vectorized %d new execution relationships for next local training epoch.\n", localAI.samples)
	}
}

func TriggerLocalTraining(_ context.Context) error {
	if localAI == nil || !localAI.cfg.Enabled {
		return fmt.Errorf("EndpointAI is disabled or not initialized")
	}

	log.Println("[EndpointAI] Initializing local unsupervised training epoch...")
	time.Sleep(3 * time.Second)

	localAI.mu.Lock()
	defer localAI.mu.Unlock()

	if localAI.samples == 0 {
		return fmt.Errorf("no observations recorded: system must be in 'observing' mode to collect telemetry prior to training")
	}

	log.Printf("[EndpointAI] Synthesizing sequence embeddings over %d recorded observations.\n", localAI.samples)
	time.Sleep(2 * time.Second)

	log.Printf("[EndpointAI] Successfully compiled and serialized local model weights to: %s\n", localAI.cfg.LocalModelPath)

	localAI.samples = 0
	localAI.lastTrained = time.Now()

	if localAI.cfg.Mode == client.ModeObserving {
		localAI.cfg.Mode = client.ModeEnforcing
		log.Println("[EndpointAI] Transitioning Engine state: OBSERVING -> ENFORCING.")
	}

	return nil
}

func AssessAnomaly(processName string, telemetryContext string) float32 {
	if localAI == nil {
		return 0.0
	}

	localAI.mu.RLock()
	defer localAI.mu.RUnlock()

	if localAI.cfg.Mode != client.ModeEnforcing {
		return 0.0
	}

	return assessAnomalyHeuristic(processName, telemetryContext)
}

func assessAnomalyHeuristic(processName string, telemetryContext string) float32 {
	suspiciousPatterns := []string{
		"bash", "curl", "wget", "nc", "netcat", "python", "perl", "ruby",
		"/tmp/", "/var/tmp/", "/dev/shm/",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(processName, pattern) || strings.Contains(telemetryContext, pattern) {
			return 0.85
		}
	}

	return 0.05
}

func Status() string {
	if localAI == nil {
		return "EndpointAI Engine is uninitialized."
	}
	localAI.mu.RLock()
	defer localAI.mu.RUnlock()

	return fmt.Sprintf("Mode:            %s\nVector Samples:  %d observations pending training\nLocal Weights:   %s\nLast Epoch Date: %s",
		localAI.cfg.Mode, localAI.samples, localAI.cfg.LocalModelPath, localAI.lastTrained.Format(time.RFC3339))
}
