//go:build linux

package scanners

import (
	"errors"
	"time"
)

type SystemVersionInfo struct {
	XProtect    XProtectVersion `json:"xprotect"`
	ClamAV      ClamAVVersion   `json:"clamav"`
	DarkScan    DarkScanVersion `json:"darkscan"`
	AI          AIVersion       `json:"ai"`
	AfterSec    string          `json:"aftersec_version"`
	CollectedAt time.Time       `json:"collected_at"`
}

type XProtectVersion struct {
	Version         string    `json:"version"`
	BuildVersion    int       `json:"build_version"`
	LastUpdate      time.Time `json:"last_update"`
	DefinitionCount int       `json:"definition_count"`
	Available       bool      `json:"available"`
	Error           string    `json:"error,omitempty"`
}

type ClamAVVersion struct {
	MainVersion     string    `json:"main_version"`
	DailyVersion    string    `json:"daily_version"`
	BytecodeVersion string    `json:"bytecode_version"`
	LastUpdate      time.Time `json:"last_update"`
	TotalSizeMB     float64   `json:"total_size_mb"`
	Available       bool      `json:"available"`
	Error           string    `json:"error,omitempty"`
}

type DarkScanVersion struct {
	EngineVersion  string   `json:"engine_version"`
	EnabledEngines []string `json:"enabled_engines"`
	YARAVersion    string   `json:"yara_version"`
	CAPAVersion    string   `json:"capa_version"`
	Available      bool     `json:"available"`
	Error          string   `json:"error,omitempty"`
}

type AIVersion struct {
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	GeminiModel    string `json:"gemini_model"`
	OpenAIModel    string `json:"openai_model"`
	AnthropicModel string `json:"anthropic_model"`
	Available      bool   `json:"available"`
}

func GetSystemVersionInfo() (*SystemVersionInfo, error) {
	return nil, errors.New("XProtect/macOS version info not available on Linux")
}

func FormatVersionInfo(_ *SystemVersionInfo) string { return "" }

func FormatVersionJSON(_ *SystemVersionInfo) (string, error) {
	return "", errors.New("not available on Linux")
}
