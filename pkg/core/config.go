package core

import (
	"crypto/rand"
	"encoding/hex"
)

type FindingOverride struct {
	Severity Severity `json:"severity"`
	Disabled bool     `json:"disabled"`
}

type Config struct {
	StrictMode       bool                        `json:"strict_mode"`
	AutoScan         bool                        `json:"auto_scan"`
	WhitelistedPaths string                      `json:"whitelisted_paths"`
	APIKey           string                      `json:"api_key,omitempty"`
	FindingOverrides map[string]FindingOverride `json:"finding_overrides,omitempty"` // key: "Category:Name"
}

func DefaultConfig() *Config {
	return &Config{
		StrictMode:       false,
		AutoScan:         false,
		WhitelistedPaths: "",
		APIKey:           generateAPIKey(),
		FindingOverrides: make(map[string]FindingOverride),
	}
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// ApplyOverrides applies user-configured overrides to findings
func (c *Config) ApplyOverrides(findings []Finding) []Finding {
	if c.FindingOverrides == nil {
		return findings
	}

	var result []Finding
	for _, f := range findings {
		key := f.Category + ":" + f.Name
		if override, exists := c.FindingOverrides[key]; exists {
			if override.Disabled {
				continue // Skip disabled findings
			}
			f.Severity = override.Severity
		}
		result = append(result, f)
	}
	return result
}

// GetFindingKey returns the unique key for a finding
func GetFindingKey(f Finding) string {
	return f.Category + ":" + f.Name
}
