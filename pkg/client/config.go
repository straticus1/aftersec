package client

import (
	"aftersec/pkg/core"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/threatintel"
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
	Provider       string `yaml:"provider"`
	Model          string `yaml:"model"`
	OpenAIKey      string `yaml:"openai_key"`
	AnthropicKey   string `yaml:"anthropic_key"`
	GeminiKey      string `yaml:"gemini_key"`
	OpenAIModel    string `yaml:"openai_model"`
	AnthropicModel string `yaml:"anthropic_model"`
	GeminiModel    string `yaml:"gemini_model"`
}

type ThreatIntelConfig struct {
	Enabled             bool     `yaml:"enabled"`
	DarkAPIKey          string   `yaml:"darkapi_key"`
	CheckCredentials    bool     `yaml:"check_credentials"`
	CheckFileHashes     bool     `yaml:"check_file_hashes"`
	CheckNetworkIOCs    bool     `yaml:"check_network_iocs"`
	MonitorDarkWeb      bool                   `yaml:"monitor_dark_web"`
	DarkWebKeywords     []string               `yaml:"darkweb_keywords"`
	OrganizationDomain  string                 `yaml:"organization_domain"`
	CredentialCheckFreq string                 `yaml:"credential_check_freq"` // daily, weekly, monthly
	MISP                threatintel.MISPConfig `yaml:"misp"`
}

type EndpointAIMode string

const (
	ModeObserving  EndpointAIMode = "observing"
	ModeTraining   EndpointAIMode = "training"
	ModeEnforcing  EndpointAIMode = "enforcing"
	ModeDisabled   EndpointAIMode = "disabled"
)

type EndpointAIConfig struct {
	Enabled          bool           `yaml:"enabled"`
	Mode             EndpointAIMode `yaml:"mode"`
	TrainingInterval string         `yaml:"training_interval"` // e.g., "ebd" or "24h"
	MaxEpochs        int            `yaml:"max_epochs"`
	LocalModelPath   string         `yaml:"local_model_path"`
}

type DaemonConfig struct {
	Scheduling   SchedulingConfig  `yaml:"scheduling"`
	Resources    ResourceConfig    `yaml:"resources"`
	Alerts       AlertConfig       `yaml:"alerts"`
	Remediation  RemediationConfig `yaml:"remediation"`
	AI           AIConfig          `yaml:"ai"`
	EndpointAI   EndpointAIConfig  `yaml:"endpoint_ai"`
	ThreatIntel  ThreatIntelConfig `yaml:"threat_intel"`
	DarkScan     darkscan.Config   `yaml:"darkscan"`
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
				Provider:       "gemini",
				Model:          "gemini-2.5-flash",
				OpenAIModel:    "gpt-4o-mini",
				AnthropicModel: "claude-3-5-sonnet-latest",
				GeminiModel:    "gemini-2.5-flash",
			},
			EndpointAI: EndpointAIConfig{
				Enabled:          true,
				Mode:             ModeObserving,
				TrainingInterval: "24h",
				MaxEpochs:        100,
				LocalModelPath:   filepath.Join(home, ".aftersec", "models", "baseline.lora"),
			},
			ThreatIntel: ThreatIntelConfig{
				Enabled:             false, // Disabled by default, requires API key
				CheckCredentials:    true,
				CheckFileHashes:     true,
				CheckNetworkIOCs:    true,
				MonitorDarkWeb:      false, // Opt-in due to API costs
				DarkWebKeywords:     []string{},
				CredentialCheckFreq: "weekly",
				MISP: threatintel.MISPConfig{
					Enabled: false,
					BaseURL: "https://misp.local",
					AuthKey: "",
				},
			},
			DarkScan: *darkscan.DefaultConfig(),
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

// SaveConfig writes the given ClientConfig back to yaml
func SaveConfig(cfg *ClientConfig, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
