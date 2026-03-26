package ai

import (
	"aftersec/pkg/client/storage"
	"context"
	"encoding/json"
	"fmt"
)

type RiskEvent struct {
	RuleName    string
	ThreatScore float64
	Context     string
	Telemetry   []map[string]any
}

type CorrelationRule interface {
	Name() string
	Query() string
	Analyze(results []map[string]any) *RiskEvent
}

type CorrelationEngine struct {
	db    storage.Manager
	rules []CorrelationRule
}

func NewCorrelationEngine(db storage.Manager) *CorrelationEngine {
	engine := &CorrelationEngine{
		db:    db,
		rules: []CorrelationRule{
			&NetworkAfterPersistenceRule{},
			&AnomalousChildProcessRule{},
			&SystemDaemonHijackRule{},
			&UnsignedExecutionRule{},
		},
	}
	return engine
}

// Run executes all behavioral correlation rules against the latest telemetry
func (e *CorrelationEngine) Run() ([]*RiskEvent, error) {
	if e.db == nil {
		return nil, fmt.Errorf("no storage manager initialized")
	}

	var allRisks []*RiskEvent
	for _, rule := range e.rules {
		results, err := e.db.QueryTelemetry(rule.Query())
		if err != nil {
			continue // Skip failed queries cleanly, log dynamically in production
		}

		if len(results) > 0 {
			risk := rule.Analyze(results)
			if risk != nil {
				allRisks = append(allRisks, risk)
			}
		}
	}
	return allRisks, nil
}

// EscalateToSwarm sends the structured attack chain directly into the Genkit Swarm for narrative triage
func (e *CorrelationEngine) EscalateToSwarm(ctx context.Context, risk *RiskEvent) (string, error) {
	b, _ := json.MarshalIndent(risk.Telemetry, "", "  ")
	prompt := fmt.Sprintf("The behavioral analytics engine fired rule '%s' (Score: %f). The attack chain context is '%s'. Read the following structured telemetry log representing the chained attack state, and provide a thorough, plain-English summary of the exact tactical intent of the adversary:\n%s",
		risk.RuleName, risk.ThreatScore, risk.Context, string(b))

	// Direct call to Genkit orchestrator (already defined via package 'ai' swarm helpers)
	return AnalyzeThreatSwarm(ctx, prompt)
}

// =========================================================================
// CORRELATION RULES
// =========================================================================

// Rule 1: Network After Persistence (Cross-Engine Correlation)
type NetworkAfterPersistenceRule struct{}

func (r *NetworkAfterPersistenceRule) Name() string { return "NetworkAfterPersistence" }

func (r *NetworkAfterPersistenceRule) Query() string {
	// Look for a process that triggered a memory anomaly/persistence flag
	// AND ALSO triggered a high-severity starlark network/policy event within 300 seconds.
	return `
	SELECT 
		f.timestamp as forensics_time,
		s.timestamp as starlark_time,
		json_extract(f.details, '$.process') as process_name,
		s.details as starlark_details
	FROM telemetry_events f
	JOIN telemetry_events s ON json_extract(f.details, '$.pid') = json_extract(s.details, '$.pid') 
	WHERE f.source = 'memory_forensics' 
	  AND s.source = 'starlark'
	  AND (strftime('%s', s.timestamp) - strftime('%s', f.timestamp)) < 300
	ORDER BY f.timestamp DESC LIMIT 10
	`
}

func (r *NetworkAfterPersistenceRule) Analyze(results []map[string]any) *RiskEvent {
	return &RiskEvent{
		RuleName:    r.Name(),
		ThreatScore: 98.0, // Instantly highly critical
		Context:     "A process exhibited memory anomaly/persistence traits, followed closely by a Starlark network event. This sequence implies successful backdoor execution reaching out to Command & Control (C2) infrastructure.",
		Telemetry:   results,
	}
}

// Rule 2: Anomalous Child Process
type AnomalousChildProcessRule struct{}

func (r *AnomalousChildProcessRule) Name() string { return "AnomalousChildProcess" }

func (r *AnomalousChildProcessRule) Query() string {
	// Identify processes classified manually string matched to Living-Off-The-Land (LotL) execution shells.
	return `
	SELECT 
		t1.timestamp,
		json_extract(t1.details, '$.process') as child_proc,
		json_extract(t1.details, '$.reason') as trigger_reason,
		json_extract(t1.details, '$.score') as base_score
	FROM telemetry_events t1
	WHERE t1.source = 'memory_forensics'
	  AND (json_extract(t1.details, '$.process') LIKE '%curl%' OR json_extract(t1.details, '$.process') LIKE '%bash%')
	  AND json_extract(t1.details, '$.score') > 40
	ORDER BY t1.timestamp DESC LIMIT 10
	`
}

func (r *AnomalousChildProcessRule) Analyze(results []map[string]any) *RiskEvent {
	return &RiskEvent{
		RuleName:    r.Name(),
		ThreatScore: 82.5,
		Context:     "Low-reputation shells or fetching utilities detected executing with anomalous process contexts. Typically indicates Living-off-the-Land (LotL) local execution bypass scripts attempting to load second-stage malware.",
		Telemetry:   results,
	}
}

// Rule 3: System Daemon Hijack
type SystemDaemonHijackRule struct{}

func (r *SystemDaemonHijackRule) Name() string { return "SystemDaemonHijack" }

func (r *SystemDaemonHijackRule) Query() string {
	// Look for a kernel EXEC event where /usr/libexec/ spawns /bin/sh or similar LotL tools, 
	// followed by a Starlark network event within 60 seconds from the same PID or its children.
	return `
	SELECT 
		e.timestamp as exec_time,
		s.timestamp as starlark_time,
		json_extract(e.details, '$.ExecPath') as spawned_shell,
		s.details as starlark_details
	FROM telemetry_events e
	JOIN telemetry_events s ON json_extract(e.details, '$.PID') = json_extract(s.details, '$.pid') 
	WHERE e.source = 'endpoint_security' 
	  AND s.source = 'starlark'
      AND e.event_type = 'notify_exec'
	  AND (json_extract(e.details, '$.ExecPath') LIKE '%/bin/sh' OR json_extract(e.details, '$.ExecPath') LIKE '%/bin/zsh' OR json_extract(e.details, '$.ExecPath') LIKE '%curl')
	  AND (strftime('%s', s.timestamp) - strftime('%s', e.timestamp)) BETWEEN 0 AND 60
	ORDER BY e.timestamp DESC LIMIT 10
	`
}

func (r *SystemDaemonHijackRule) Analyze(results []map[string]any) *RiskEvent {
	return &RiskEvent{
		RuleName:    r.Name(),
		ThreatScore: 92.0,
		Context:     "A system-level process unexpectedly spawned a shell interpreter or fetch tool which subsequently made an anomalous network connection. This is highly indicative of a remote code execution (RCE) payload successfully dropping into a reverse shell.",
		Telemetry:   results,
	}
}

// Rule 4: Unsigned Execution
type UnsignedExecutionRule struct{}

func (r *UnsignedExecutionRule) Name() string { return "UnsignedExecution" }

func (r *UnsignedExecutionRule) Query() string {
	// Basic ESF correlation: look for raw EXEC telemetry in tmp or hidden directories 
    // immediately triggering a memory forensics anomaly.
	return `
	SELECT 
		e.timestamp as exec_time,
		f.timestamp as forensics_time,
		json_extract(e.details, '$.ExecPath') as binary_path,
		json_extract(f.details, '$.reason') as forensics_reason
	FROM telemetry_events e
	JOIN telemetry_events f ON json_extract(e.details, '$.PID') = json_extract(f.details, '$.pid') 
	WHERE e.source = 'endpoint_security' 
	  AND f.source = 'memory_forensics'
      AND e.event_type = 'notify_exec'
	  AND (json_extract(e.details, '$.ExecPath') LIKE '%/tmp/%' OR json_extract(e.details, '$.ExecPath') LIKE '%/.*')
	  AND (strftime('%s', f.timestamp) - strftime('%s', e.timestamp)) BETWEEN 0 AND 120
	ORDER BY e.timestamp DESC LIMIT 10
	`
}

func (r *UnsignedExecutionRule) Analyze(results []map[string]any) *RiskEvent {
	return &RiskEvent{
		RuleName:    r.Name(),
		ThreatScore: 88.5,
		Context:     "An executable was launched from a highly suspicious directory (TMP or hidden folder) and subsequently triggered a deep memory anomaly (e.g., unsigned memory-mapping or code injection). This represents malware attempting to bypass static file analysis by unpacking in memory.",
		Telemetry:   results,
	}
}
