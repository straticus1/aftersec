package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
	"aftersec/pkg/edr"
)

// BehavioralAnomaly represents a detected behavioral anomaly
type BehavioralAnomaly struct {
	ID            string
	EndpointID    string
	ProcessTree   []ProcessNode
	AnomalyType   string
	AnomalyScore  float64
	Features      map[string]float64
	Indicators    []string
	Timestamp     time.Time
	Remediation   string
	Severity      string
}

// ProcessNode represents a node in the process execution tree
type ProcessNode struct {
	PID         int
	PPID        int
	ProcessName string
	ExecPath    string
	Args        []string
	User        string
	Timestamp   time.Time
	Children    []*ProcessNode
}

// BehavioralFeatures represents extracted features for ML analysis
type BehavioralFeatures struct {
	// Process characteristics
	ProcessChainDepth      int
	UniqueProcessCount     int
	ShellInvocations       int
	ScriptInterpreterCount int

	// Command-line features
	ObfuscationScore       float64
	CommandComplexity      float64
	Base64EncodingDetected bool
	URLInCommand           bool

	// Network behavior
	NetworkConnectionCount int
	UniqueDestinations     int
	HTTPSRatio             float64
	SuspiciousPortsUsed    bool

	// File system behavior
	FileCreationCount      int
	FileModificationCount  int
	SensitivePathsAccessed bool
	TempDirectoryActivity  bool

	// Temporal features
	ExecutionDuration      time.Duration
	NightTimeExecution     bool
	RapidSuccession        bool

	// Privilege features
	PrivilegeEscalation    bool
	RootExecution          bool
	SudoUsage              bool
}

// BehavioralAnalyticsEngine performs advanced behavioral analysis
type BehavioralAnalyticsEngine struct {
	mu                sync.RWMutex
	processHistory    map[int]*ProcessNode
	baselineProfiles  map[string]*BehavioralProfile
	anomalyThreshold  float64
	db                storage.Manager
	eventBuffer       chan edr.ProcessEvent
	stopChan          chan struct{}
}

// BehavioralProfile represents normal behavior baseline for a process
type BehavioralProfile struct {
	ProcessName    string
	AvgChainDepth  float64
	AvgNetworkConn float64
	AvgFileOps     float64
	CommonArgs     map[string]int
	LastUpdated    time.Time
}

var behavioralEngine *BehavioralAnalyticsEngine
var behavioralOnce sync.Once

// InitBehavioralAnalytics initializes the behavioral analytics engine
func InitBehavioralAnalytics(db storage.Manager) *BehavioralAnalyticsEngine {
	behavioralOnce.Do(func() {
		behavioralEngine = &BehavioralAnalyticsEngine{
			processHistory:   make(map[int]*ProcessNode),
			baselineProfiles: make(map[string]*BehavioralProfile),
			anomalyThreshold: 0.7,
			db:               db,
			eventBuffer:      make(chan edr.ProcessEvent, 1000),
			stopChan:         make(chan struct{}),
		}

		// Load baseline profiles from database
		behavioralEngine.loadBaselines()

		// Start event processing goroutine
		go behavioralEngine.processEvents()
	})
	return behavioralEngine
}

// AnalyzeEvent processes an EDR event and checks for anomalies
func (ba *BehavioralAnalyticsEngine) AnalyzeEvent(event edr.ProcessEvent) (*BehavioralAnomaly, error) {
	// Add to buffer for processing
	select {
	case ba.eventBuffer <- event:
	default:
		// Buffer full, drop event (or handle differently)
	}

	// Extract features from event
	features := ba.extractFeatures(event)

	// Build process tree
	processTree := ba.buildProcessTree(event)

	// Calculate anomaly score
	anomalyScore := ba.calculateAnomalyScore(event, features)

	// Check if score exceeds threshold
	if anomalyScore < ba.anomalyThreshold {
		return nil, nil // Not anomalous
	}

	// Classify anomaly type
	anomalyType, indicators := ba.classifyAnomaly(event, features)

	anomaly := &BehavioralAnomaly{
		ID:           fmt.Sprintf("anomaly-%d-%d", time.Now().Unix(), event.PID),
		ProcessTree:  processTree,
		AnomalyType:  anomalyType,
		AnomalyScore: anomalyScore,
		Features:     featuresToMap(features),
		Indicators:   indicators,
		Timestamp:    time.Now(),
		Remediation:  generateRemediation(anomalyType, event),
		Severity:     severityFromScore(anomalyScore),
	}

	// Log to database
	if ba.db != nil {
		ba.db.LogTelemetryEvent(
			"behavioral_anomaly",
			anomalyType,
			anomaly.Severity,
			fmt.Sprintf(`{"pid": %d, "process": "%s", "score": %.2f}`,
				event.PID, event.ExecPath, anomalyScore),
		)
	}

	return anomaly, nil
}

// extractFeatures extracts behavioral features from an event
func (ba *BehavioralAnalyticsEngine) extractFeatures(event edr.ProcessEvent) *BehavioralFeatures {
	features := &BehavioralFeatures{}

	// Process chain analysis
	features.ProcessChainDepth = ba.getProcessChainDepth(event.PID)

	// Command-line analysis
	if len(event.Args) > 0 {
		cmdLine := strings.Join(event.Args, " ")

		// Obfuscation detection
		features.ObfuscationScore = detectObfuscation(cmdLine)
		features.CommandComplexity = calculateCommandComplexity(cmdLine)
		features.Base64EncodingDetected = containsBase64(cmdLine)
		features.URLInCommand = containsURL(cmdLine)

		// Shell detection
		if isShellInvocation(event.ExecPath) {
			features.ShellInvocations = 1
		}

		// Script interpreter detection
		if isScriptInterpreter(event.ExecPath) {
			features.ScriptInterpreterCount = 1
		}
	}

	// Temporal features
	hour := event.Timestamp.Hour()
	features.NightTimeExecution = hour >= 22 || hour <= 6

	// Privilege features
	features.RootExecution = event.UID == 0
	features.SudoUsage = strings.Contains(event.ExecPath, "sudo")

	// Sensitive path access
	features.SensitivePathsAccessed = checkSensitivePathAccess(event.ExecPath)
	features.TempDirectoryActivity = strings.Contains(event.ExecPath, "/tmp") || strings.Contains(event.ExecPath, "/var/tmp")

	return features
}

// calculateAnomalyScore uses multiple detection techniques to score anomaly
func (ba *BehavioralAnalyticsEngine) calculateAnomalyScore(event edr.ProcessEvent, features *BehavioralFeatures) float64 {
	score := 0.0

	// 1. Isolation Forest-style anomaly detection (simplified)
	score += ba.isolationForestScore(features) * 0.3

	// 2. Baseline deviation score
	score += ba.baselineDeviationScore(event, features) * 0.3

	// 3. Rule-based heuristics
	score += ba.heuristicScore(features) * 0.4

	return min(score, 1.0)
}

// isolationForestScore implements simplified isolation forest algorithm
func (ba *BehavioralAnalyticsEngine) isolationForestScore(features *BehavioralFeatures) float64 {
	// Isolation Forest: anomalies require fewer splits to isolate
	// Simplified version: calculate average path length for feature isolation

	avgPathLength := 0.0
	featureCount := 0

	// For each numeric feature, estimate isolation depth
	if features.ProcessChainDepth > 5 {
		avgPathLength += 2.0 // Shallow path = anomaly
		featureCount++
	} else {
		avgPathLength += 8.0 // Deep path = normal
		featureCount++
	}

	if features.ObfuscationScore > 0.5 {
		avgPathLength += 3.0
		featureCount++
	} else {
		avgPathLength += 7.0
		featureCount++
	}

	if features.NetworkConnectionCount > 10 {
		avgPathLength += 2.5
		featureCount++
	} else {
		avgPathLength += 6.5
		featureCount++
	}

	if featureCount == 0 {
		return 0.0
	}

	avgPathLength /= float64(featureCount)

	// Convert path length to anomaly score (shorter path = higher anomaly)
	// Normalize: typical path length is ~7, anomalous is ~3
	normalizedScore := 1.0 - (avgPathLength / 10.0)
	return max(0.0, normalizedScore)
}

// baselineDeviationScore compares behavior against learned baseline
func (ba *BehavioralAnalyticsEngine) baselineDeviationScore(event edr.ProcessEvent, features *BehavioralFeatures) float64 {
	processName := getProcessName(event.ExecPath)

	ba.mu.RLock()
	baseline, exists := ba.baselineProfiles[processName]
	ba.mu.RUnlock()

	if !exists {
		// No baseline = slightly suspicious but not critical
		return 0.3
	}

	// Calculate deviation from baseline
	deviationScore := 0.0

	// Chain depth deviation
	chainDepthDev := math.Abs(float64(features.ProcessChainDepth) - baseline.AvgChainDepth)
	if chainDepthDev > 2.0 {
		deviationScore += 0.3
	}

	// Network connection deviation
	netConnDev := math.Abs(float64(features.NetworkConnectionCount) - baseline.AvgNetworkConn)
	if netConnDev > 5.0 {
		deviationScore += 0.3
	}

	// File operation deviation
	fileOpsDev := math.Abs(float64(features.FileCreationCount+features.FileModificationCount) - baseline.AvgFileOps)
	if fileOpsDev > 10.0 {
		deviationScore += 0.3
	}

	// Check if arguments match common patterns
	cmdLine := strings.Join(event.Args, " ")
	if !baseline.hasCommonArgs(cmdLine) {
		deviationScore += 0.1
	}

	return min(deviationScore, 1.0)
}

// heuristicScore applies rule-based detection
func (ba *BehavioralAnalyticsEngine) heuristicScore(features *BehavioralFeatures) float64 {
	score := 0.0

	// Obfuscation is highly suspicious
	if features.ObfuscationScore > 0.7 {
		score += 0.4
	}

	// Base64 in command line
	if features.Base64EncodingDetected {
		score += 0.2
	}

	// Root execution with shell
	if features.RootExecution && features.ShellInvocations > 0 {
		score += 0.3
	}

	// Night-time execution + network activity
	if features.NightTimeExecution && features.NetworkConnectionCount > 0 {
		score += 0.2
	}

	// Accessing sensitive paths
	if features.SensitivePathsAccessed {
		score += 0.3
	}

	// Privilege escalation
	if features.PrivilegeEscalation {
		score += 0.5
	}

	// Temp directory activity with network
	if features.TempDirectoryActivity && features.NetworkConnectionCount > 0 {
		score += 0.3
	}

	return min(score, 1.0)
}

// classifyAnomaly determines the type of behavioral anomaly
func (ba *BehavioralAnalyticsEngine) classifyAnomaly(event edr.ProcessEvent, features *BehavioralFeatures) (string, []string) {
	indicators := []string{}

	// Lateral movement detection
	if features.NetworkConnectionCount > 5 && features.SudoUsage {
		indicators = append(indicators, "Potential lateral movement")
		return "lateral_movement", indicators
	}

	// Data exfiltration detection
	if features.NetworkConnectionCount > 10 && features.FileCreationCount > 20 {
		indicators = append(indicators, "High file activity + network transfers")
		return "data_exfiltration", indicators
	}

	// Credential dumping
	if features.SensitivePathsAccessed && features.RootExecution {
		indicators = append(indicators, "Root access to sensitive paths")
		return "credential_access", indicators
	}

	// Persistence mechanism
	if strings.Contains(event.ExecPath, "LaunchAgents") || strings.Contains(event.ExecPath, "LaunchDaemons") {
		indicators = append(indicators, "Launch agent/daemon modification")
		return "persistence", indicators
	}

	// Privilege escalation
	if features.PrivilegeEscalation {
		indicators = append(indicators, "Privilege escalation detected")
		return "privilege_escalation", indicators
	}

	// Command and control
	if features.NetworkConnectionCount > 0 && features.ObfuscationScore > 0.5 {
		indicators = append(indicators, "Obfuscated network communication")
		return "command_and_control", indicators
	}

	// Defense evasion
	if features.ObfuscationScore > 0.7 {
		indicators = append(indicators, "High obfuscation score")
		return "defense_evasion", indicators
	}

	// Default: general suspicious behavior
	if features.ProcessChainDepth > 5 {
		indicators = append(indicators, "Deep process chain")
	}
	if features.Base64EncodingDetected {
		indicators = append(indicators, "Base64 encoding in command")
	}

	return "suspicious_behavior", indicators
}

// buildProcessTree constructs the execution tree
func (ba *BehavioralAnalyticsEngine) buildProcessTree(event edr.ProcessEvent) []ProcessNode {
	tree := []ProcessNode{}

	node := ProcessNode{
		PID:         event.PID,
		PPID:        event.PPID,
		ProcessName: getProcessName(event.ExecPath),
		ExecPath:    event.ExecPath,
		Args:        event.Args,
		Timestamp:   event.Timestamp,
		Children:    []*ProcessNode{},
	}

	tree = append(tree, node)

	// In production, walk up the parent chain and down the children
	// For now, return single node

	return tree
}

// processEvents continuously processes buffered events
func (ba *BehavioralAnalyticsEngine) processEvents() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event := <-ba.eventBuffer:
			// Update process history
			ba.mu.Lock()
			node := &ProcessNode{
				PID:         event.PID,
				PPID:        event.PPID,
				ProcessName: getProcessName(event.ExecPath),
				ExecPath:    event.ExecPath,
				Timestamp:   event.Timestamp,
			}
			ba.processHistory[event.PID] = node
			ba.mu.Unlock()

			// Update baselines (training mode)
			ba.updateBaseline(event)

		case <-ticker.C:
			// Periodic cleanup of old process history
			ba.cleanupProcessHistory()

		case <-ba.stopChan:
			return
		}
	}
}

// updateBaseline updates the behavioral baseline for a process
func (ba *BehavioralAnalyticsEngine) updateBaseline(event edr.ProcessEvent) {
	processName := getProcessName(event.ExecPath)

	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile, exists := ba.baselineProfiles[processName]
	if !exists {
		profile = &BehavioralProfile{
			ProcessName: processName,
			CommonArgs:  make(map[string]int),
		}
		ba.baselineProfiles[processName] = profile
	}

	// Update moving averages (exponential moving average)
	alpha := 0.1 // smoothing factor

	chainDepth := float64(ba.getProcessChainDepth(event.PID))
	profile.AvgChainDepth = alpha*chainDepth + (1-alpha)*profile.AvgChainDepth

	// Track common arguments
	cmdLine := strings.Join(event.Args, " ")
	profile.CommonArgs[cmdLine]++

	profile.LastUpdated = time.Now()
}

// loadBaselines loads behavioral baselines from database
func (ba *BehavioralAnalyticsEngine) loadBaselines() {
	// In production, load from database
	// For now, initialize empty
}

// saveBaselines persists baselines to database
func (ba *BehavioralAnalyticsEngine) SaveBaselines() error {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	for _, profile := range ba.baselineProfiles {
		data, err := json.Marshal(profile)
		if err != nil {
			continue
		}

		if ba.db != nil {
			ba.db.LogTelemetryEvent(
				"behavioral_baseline",
				profile.ProcessName,
				"info",
				string(data),
			)
		}
	}

	return nil
}

// Helper functions

func (ba *BehavioralAnalyticsEngine) getProcessChainDepth(pid int) int {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	depth := 0
	currentPID := pid

	for depth < 100 { // Prevent infinite loops
		node, exists := ba.processHistory[currentPID]
		if !exists || node.PPID == 0 || node.PPID == currentPID {
			break
		}
		currentPID = node.PPID
		depth++
	}

	return depth
}

func (ba *BehavioralAnalyticsEngine) cleanupProcessHistory() {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	now := time.Now()
	for pid, node := range ba.processHistory {
		if now.Sub(node.Timestamp) > 1*time.Hour {
			delete(ba.processHistory, pid)
		}
	}
}

func (bp *BehavioralProfile) hasCommonArgs(cmdLine string) bool {
	// Check if command line matches any common patterns
	for commonArg := range bp.CommonArgs {
		if strings.Contains(cmdLine, commonArg) {
			return true
		}
	}
	return false
}

func detectObfuscation(cmdLine string) float64 {
	score := 0.0

	// Check for various obfuscation techniques
	if strings.Count(cmdLine, "$") > 5 {
		score += 0.3 // Variable expansion
	}
	if strings.Contains(cmdLine, "\\x") || strings.Contains(cmdLine, "\\u") {
		score += 0.3 // Hex/unicode escaping
	}
	if strings.Count(cmdLine, "`") > 3 {
		score += 0.2 // Command substitution
	}
	if hasExcessiveWhitespace(cmdLine) {
		score += 0.2
	}

	return min(score, 1.0)
}

func calculateCommandComplexity(cmdLine string) float64 {
	// Measure command complexity based on length, special chars, nesting
	complexity := 0.0

	length := float64(len(cmdLine))
	complexity += min(length/500.0, 1.0) * 0.4

	specialChars := strings.Count(cmdLine, "|") + strings.Count(cmdLine, "&&") +
		strings.Count(cmdLine, "||") + strings.Count(cmdLine, ";")
	complexity += min(float64(specialChars)/10.0, 1.0) * 0.6

	return min(complexity, 1.0)
}

func containsBase64(cmdLine string) bool {
	// Simple heuristic: long alphanumeric strings with specific patterns
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	return base64Pattern.MatchString(cmdLine)
}

func containsURL(cmdLine string) bool {
	return strings.Contains(cmdLine, "http://") || strings.Contains(cmdLine, "https://")
}

func isShellInvocation(execPath string) bool {
	shells := []string{"bash", "sh", "zsh", "fish", "ksh", "tcsh", "csh"}
	for _, shell := range shells {
		if strings.HasSuffix(execPath, shell) {
			return true
		}
	}
	return false
}

func isScriptInterpreter(execPath string) bool {
	interpreters := []string{"python", "python3", "ruby", "perl", "php", "node", "lua"}
	for _, interp := range interpreters {
		if strings.Contains(execPath, interp) {
			return true
		}
	}
	return false
}

func checkSensitivePathAccess(execPath string) bool {
	sensitivePaths := []string{
		"/etc/sudoers",
		"/etc/shadow",
		"/etc/passwd",
		"/Library/Keychains",
		"/.ssh",
		"/var/db/dslocal",
	}

	for _, path := range sensitivePaths {
		if strings.Contains(execPath, path) {
			return true
		}
	}
	return false
}

func hasExcessiveWhitespace(cmdLine string) bool {
	whitespaceCount := strings.Count(cmdLine, "  ") + strings.Count(cmdLine, "\t")
	return whitespaceCount > 10
}

func getProcessName(execPath string) string {
	parts := strings.Split(execPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return execPath
}

func featuresToMap(features *BehavioralFeatures) map[string]float64 {
	return map[string]float64{
		"process_chain_depth":      float64(features.ProcessChainDepth),
		"obfuscation_score":        features.ObfuscationScore,
		"command_complexity":       features.CommandComplexity,
		"network_connections":      float64(features.NetworkConnectionCount),
		"file_operations":          float64(features.FileCreationCount + features.FileModificationCount),
	}
}

func generateRemediation(anomalyType string, event edr.ProcessEvent) string {
	remediations := map[string]string{
		"lateral_movement":      "Block network access for PID %d. Investigate user account for compromise.",
		"data_exfiltration":     "Terminate PID %d immediately. Review network logs for exfiltration destinations.",
		"credential_access":     "Kill PID %d. Force password reset for all users. Review access logs.",
		"persistence":           "Remove persistence mechanism. Terminate PID %d.",
		"privilege_escalation":  "Terminate PID %d. Review sudo logs and privilege grants.",
		"command_and_control":   "Block network for PID %d. Analyze C2 infrastructure.",
		"defense_evasion":       "Terminate PID %d. Perform memory forensics.",
		"suspicious_behavior":   "Monitor PID %d closely. Consider termination if behavior continues.",
	}

	template, exists := remediations[anomalyType]
	if !exists {
		template = "Investigate PID %d for suspicious activity."
	}

	return fmt.Sprintf(template, event.PID)
}

func severityFromScore(score float64) string {
	if score >= 0.9 {
		return "critical"
	} else if score >= 0.7 {
		return "high"
	} else if score >= 0.5 {
		return "medium"
	}
	return "low"
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
