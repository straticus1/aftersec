package ai

import (
	"aftersec/pkg/client/storage"
)

type ThreatEvaluator struct {
	db storage.Manager
}

func NewThreatEvaluator(db storage.Manager) *ThreatEvaluator {
	return &ThreatEvaluator{db: db}
}

// EvaluateProcess dynamically adjusts threat scores by leveraging historical relational context from SQLite.
func (e *ThreatEvaluator) EvaluateProcess(pid int, currentScore float64, reason string) (float64, string) {
	if e.db == nil {
		return currentScore, reason
	}
	
	// Query telemetry database for recent anomalous Starlark behavior or other factors
	events, err := e.db.QueryTelemetry("SELECT * FROM telemetry_events WHERE source = 'starlark' AND timestamp > datetime('now', '-5 minutes') LIMIT 1")
	if err == nil && len(events) > 0 {
		// Compounding relational threat triggers a critical escalation!
		return currentScore + 20.0, reason + " [Escalated via Starlark Relational DB Match]"
	}
	
	return currentScore, reason
}
