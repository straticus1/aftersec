package client

import (
	"aftersec/pkg/core"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// StorageType represents the storage backend to use
type StorageType string

const (
	StorageLocal StorageType = "local"
	StorageCache StorageType = "cache"
)

type StorageConfig struct {
	Type StorageType `yaml:"type"`
	Path string      `yaml:"path"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

type ServerConfig struct {
	Address         string    `yaml:"address"`
	TLS             TLSConfig `yaml:"tls"`
	EnrollmentToken string    `yaml:"enrollment_token"`
}

type SchedulingConfig struct {
	ScanInterval      string `yaml:"scan_interval"`
	Adaptive          bool   `yaml:"adaptive"`
	HighRiskInterval  string `yaml:"high_risk_interval"`
	QuietHoursEnabled bool   `yaml:"quiet_hours_enabled"`
	QuietHoursStart   string `yaml:"quiet_hours_start"`
	QuietHoursEnd     string `yaml:"quiet_hours_end"`
}

type ResourceConfig struct {
	MaxCPUPercent  int    `yaml:"max_cpu_percent"`
	MaxMemoryMB    int    `yaml:"max_memory_mb"`
	PauseOnBattery bool   `yaml:"pause_on_battery"`
	MaxWorkers     int    `yaml:"max_workers"`
	Priority       string `yaml:"priority"`
}

type AlertConfig struct {
	AlertOnCritical bool `yaml:"alert_on_critical"`
	AlertOnHigh     bool `yaml:"alert_on_high"`
}

type RemediationConfig struct {
	AutoRemediate bool `yaml:"auto_remediate"`
}

type AIConfig struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
}

type DaemonConfig struct {
	Scheduling  SchedulingConfig  `yaml:"scheduling"`
	Resources   ResourceConfig    `yaml:"resources"`
	Alerts      AlertConfig       `yaml:"alerts"`
	Remediation RemediationConfig `yaml:"remediation"`
	AI          AIConfig          `yaml:"ai"`
}

// ClientConfig represents the client-side configuration
type ClientConfig struct {
	Mode     OperationMode `yaml:"mode"`
	TenantID string        `yaml:"tenant_id"`
	Storage  StorageConfig `yaml:"storage"`
	Server   *ServerConfig `yaml:"server,omitempty"`
	Daemon   DaemonConfig  `yaml:"daemon"`

	// Embed core.Config values
	Core core.Config `yaml:"core,omitempty"`
}

// DefaultClientConfig returns a standalone configuration
func DefaultClientConfig() *ClientConfig {
	home, _ := os.UserHomeDir()
	return &ClientConfig{
		Mode: ModeStandalone,
		Storage: StorageConfig{
			Type: StorageLocal,
			Path: filepath.Join(home, ".aftersec"),
		},
		Daemon: DaemonConfig{
			Scheduling: SchedulingConfig{
				ScanInterval:      "6h",
				Adaptive:          true,
				HighRiskInterval:  "30m",
				QuietHoursEnabled: false,
			},
			Resources: ResourceConfig{
				MaxCPUPercent:  25,
				MaxMemoryMB:    500,
				PauseOnBattery: true,
				MaxWorkers:     2,
				Priority:       "background",
			},
			Alerts: AlertConfig{
				AlertOnCritical: true,
				AlertOnHigh:     false,
			},
			Remediation: RemediationConfig{
				AutoRemediate: false,
			},
			AI: AIConfig{
				Provider: "gemini",
				Model:    "gemini-2.5-flash",
			},
		},
		Core: *core.DefaultConfig(),
	}
}

// LoadConfig reads the config file from the standard location
func LoadConfig(path string) (*ClientConfig, error) {
	cfg := DefaultClientConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config file %s: %w", path, err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}

	// Env overrides
	if mode := os.Getenv("AFTERSEC_MODE"); mode != "" {
		cfg.Mode = OperationMode(mode)
	}

	if !cfg.Mode.IsValid() {
		return nil, fmt.Errorf("invalid operation mode: %s", cfg.Mode)
	}

	return cfg, nil
}
