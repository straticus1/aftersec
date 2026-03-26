package storage

import (
	"aftersec/pkg/core"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// LocalManager implements the Manager interface for local disk storage
type LocalManager struct {
	baseDir string
	mu      sync.RWMutex
}

// NewLocalManager creates a new standalone local storage manager
func NewLocalManager(baseDir string) (*LocalManager, error) {
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".aftersec")
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create base dir: %w", err)
	}
	return &LocalManager{baseDir: baseDir}, nil
}

func (m *LocalManager) SaveCommit(state *core.SecurityState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	filename := fmt.Sprintf("commit_%d.json", state.Timestamp.Unix())
	path := filepath.Join(m.baseDir, filename)

	if !filepath.IsAbs(path) || !isSubPath(m.baseDir, path) {
		return fmt.Errorf("invalid path")
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

func isSubPath(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && rel != ".." && !filepath.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (m *LocalManager) GetHistory() ([]*core.SecurityState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	files, err := os.ReadDir(m.baseDir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	var history []*core.SecurityState
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".json" {
			path := filepath.Join(m.baseDir, f.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var st core.SecurityState
			if err := json.Unmarshal(data, &st); err == nil {
				history = append(history, &st)
			}
		}
	}

	sort.Slice(history, func(i, j int) bool {
		return history[i].Timestamp.After(history[j].Timestamp)
	})

	return history, nil
}

func (m *LocalManager) GetLatest() (*core.SecurityState, error) {
	history, err := m.GetHistory()
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, nil
	}
	return history[0], nil
}

func (m *LocalManager) GetConfigPath() string {
	return filepath.Join(m.baseDir, "settings.json")
}

func (m *LocalManager) LoadConfig() (*core.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	path := m.GetConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return core.DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := core.DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return cfg, nil
}

func (m *LocalManager) SaveConfig(cfg *core.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := m.GetConfigPath()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func (m *LocalManager) LogTelemetryEvent(source, eventType, severity, details string) error {
	return nil
}

func (m *LocalManager) QueryTelemetry(query string, args ...any) ([]map[string]any, error) {
	return nil, fmt.Errorf("telemetry query not supported in local file manager")
}

func (m *LocalManager) PruneTelemetry(hours int) (int64, error) {
	return 0, nil
}

func (m *LocalManager) GetUnsyncedTelemetry(limit int) ([]map[string]any, error) {
	return nil, nil
}

func (m *LocalManager) MarkTelemetrySynced(ids []int) error {
	return nil
}
