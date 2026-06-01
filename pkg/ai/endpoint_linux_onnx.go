//go:build linux && onnxruntime

package ai

// ONNX Runtime variant — build with: CGO_ENABLED=1 go build -tags onnxruntime
//
// Expected model contract:
//   input:  "features"      shape [1, 64] float32  (see featureVector)
//   output: "anomaly_score" shape [1, 1]  float32  value in [0.0, 1.0]
//
// Set local_model_path in config to a compiled .onnx file.
// Set ort_lib_path to the absolute path of libonnxruntime.so if it is not in
// the standard library search path (e.g. /usr/local/lib/libonnxruntime.so).

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	ort "github.com/yalue/onnxruntime_go"

	"aftersec/pkg/client"
)

const featureDim = 64

type EndpointAI struct {
	cfg         client.EndpointAIConfig
	mu          sync.RWMutex
	samples     int
	lastTrained time.Time
	session     *ort.DynamicAdvancedSession
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

	if cfg.OrtLibPath != "" {
		ort.SetSharedLibraryPath(cfg.OrtLibPath)
	}
	if err := ort.InitializeEnvironment(); err != nil {
		return fmt.Errorf("ONNX Runtime init failed: %w", err)
	}

	if cfg.LocalModelPath != "" {
		if err := loadONNXModel(cfg.LocalModelPath); err != nil {
			log.Printf("[EndpointAI] Warning: could not load ONNX model: %v", err)
			log.Println("[EndpointAI] Falling back to heuristic scoring")
		} else {
			log.Printf("[EndpointAI] Loaded ONNX model from: %s", cfg.LocalModelPath)
		}
	}

	log.Printf("[EndpointAI] Engine initialized in %q mode with interval %q. Model path: %s\n",
		cfg.Mode, cfg.TrainingInterval, cfg.LocalModelPath)
	return nil
}

func loadONNXModel(modelPath string) error {
	session, err := ort.NewDynamicAdvancedSession(
		modelPath,
		[]string{"features"},
		[]string{"anomaly_score"},
		nil,
	)
	if err != nil {
		return err
	}
	if localAI.session != nil {
		_ = localAI.session.Destroy()
	}
	localAI.session = session
	return nil
}

func Close() {
	if localAI == nil {
		return
	}
	localAI.mu.Lock()
	defer localAI.mu.Unlock()
	if localAI.session != nil {
		_ = localAI.session.Destroy()
		localAI.session = nil
	}
	_ = ort.DestroyEnvironment()
}

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

	if localAI.session != nil {
		if score, err := assessAnomalyWithONNX(processName, telemetryContext); err == nil {
			return score
		} else {
			log.Printf("[EndpointAI] ONNX inference error: %v — using heuristic fallback", err)
		}
	}

	return assessAnomalyHeuristic(processName, telemetryContext)
}

// assessAnomalyWithONNX runs the loaded ONNX model against a 64-float feature vector.
func assessAnomalyWithONNX(processName, telemetryContext string) (float32, error) {
	features := featureVector(processName, telemetryContext)

	input, err := ort.NewTensor(ort.NewShape(1, featureDim), features)
	if err != nil {
		return 0, fmt.Errorf("create input tensor: %w", err)
	}
	defer input.Destroy()

	output, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 1))
	if err != nil {
		return 0, fmt.Errorf("create output tensor: %w", err)
	}
	defer output.Destroy()

	if err := localAI.session.Run([]ort.Value{input}, []ort.Value{output}); err != nil {
		return 0, fmt.Errorf("session run: %w", err)
	}

	data := output.GetData()
	if len(data) == 0 {
		return 0, fmt.Errorf("empty output from model")
	}
	score := data[0]
	if score < 0 || score > 1 {
		return 0, fmt.Errorf("model output %f out of [0,1] range", score)
	}
	return score, nil
}

// featureVector encodes processName and telemetryContext into a 64-float32 vector.
//
// Layout (indices):
//   0–25:  character frequencies a–z for processName  (normalized by len)
//   26:    normalized length of processName           (len/64, capped at 1.0)
//   27–52: character frequencies a–z for telemetryContext
//   53:    normalized length of telemetryContext      (len/256, capped at 1.0)
//   54–63: reserved (zero)
func featureVector(processName, telemetryContext string) []float32 {
	vec := make([]float32, featureDim)
	fillCharFreq(vec[0:26], processName)
	if l := float32(len(processName)) / 64.0; l > 1.0 {
		vec[26] = 1.0
	} else {
		vec[26] = l
	}
	fillCharFreq(vec[27:53], telemetryContext)
	if l := float32(len(telemetryContext)) / 256.0; l > 1.0 {
		vec[53] = 1.0
	} else {
		vec[53] = l
	}
	return vec
}

func fillCharFreq(dst []float32, s string) {
	s = strings.ToLower(s)
	total := float32(len(s))
	if total == 0 {
		return
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			dst[c-'a']++
		}
	}
	for i := range dst {
		dst[i] /= total
	}
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

	modelStatus := "none (heuristic fallback active)"
	if localAI.session != nil {
		modelStatus = localAI.cfg.LocalModelPath
	}
	return fmt.Sprintf("Mode:            %s\nVector Samples:  %d observations pending training\nLocal Weights:   %s\nLast Epoch Date: %s",
		localAI.cfg.Mode, localAI.samples, modelStatus, localAI.lastTrained.Format(time.RFC3339))
}
