package storage

import (
	"aftersec/pkg/core"
)

// Manager defines the generic storage backend operations
type Manager interface {
	SaveCommit(state *core.SecurityState) error
	GetHistory() ([]*core.SecurityState, error)
	GetLatest() (*core.SecurityState, error)
	GetConfigPath() string
	LoadConfig() (*core.Config, error)
	SaveConfig(cfg *core.Config) error
	LogTelemetryEvent(source, eventType, severity, details string) error
	QueryTelemetry(query string, args ...any) ([]map[string]any, error)
	PruneTelemetry(hours int) (int64, error)
	GetUnsyncedTelemetry(limit int) ([]map[string]any, error)
	MarkTelemetrySynced(ids []int) error
}
