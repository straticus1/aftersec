package storage

import (
	"aftersec/pkg/client"
	"aftersec/pkg/core"
	"fmt"
	"log"
)

// CacheManager implements the Manager interface for enterprise mode caching
type CacheManager struct {
	local  *LocalManager
	server *client.ServerConfig
}

// NewCacheManager creates a storage manager that syncs to the enterprise server
func NewCacheManager(cfg *client.ClientConfig) (*CacheManager, error) {
	if cfg.Server == nil {
		return nil, fmt.Errorf("server config required for cache manager")
	}

	local, err := NewLocalManager(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("init local cache: %w", err)
	}

	return &CacheManager{
		local:  local,
		server: cfg.Server,
	}, nil
}

func (m *CacheManager) SaveCommit(state *core.SecurityState) error {
	// First save locally (offline queue)
	if err := m.local.SaveCommit(state); err != nil {
		return err
	}

	// In a real implementation, this would asynchronously upload findings to the gRPC server
	log.Printf("[Enterprise] Queued scan %d for upload to %s", state.Timestamp.Unix(), m.server.Address)
	return nil
}

func (m *CacheManager) GetHistory() ([]*core.SecurityState, error) {
	return m.local.GetHistory()
}

func (m *CacheManager) GetLatest() (*core.SecurityState, error) {
	return m.local.GetLatest()
}

func (m *CacheManager) GetConfigPath() string {
	return m.local.GetConfigPath()
}

func (m *CacheManager) LoadConfig() (*core.Config, error) {
	return m.local.LoadConfig()
}

func (m *CacheManager) SaveConfig(cfg *core.Config) error {
	return m.local.SaveConfig(cfg)
}

func (m *CacheManager) LogTelemetryEvent(source, eventType, severity, details string) error {
	return m.local.LogTelemetryEvent(source, eventType, severity, details)
}

func (m *CacheManager) QueryTelemetry(query string, args ...any) ([]map[string]any, error) {
	return m.local.QueryTelemetry(query, args...)
}

func (m *CacheManager) PruneTelemetry(hours int) (int64, error) {
	return m.local.PruneTelemetry(hours)
}

func (m *CacheManager) GetUnsyncedTelemetry(limit int) ([]map[string]any, error) {
	return m.local.GetUnsyncedTelemetry(limit)
}

func (m *CacheManager) MarkTelemetrySynced(ids []int) error {
	return m.local.MarkTelemetrySynced(ids)
}
