package core

import (
	"crypto/rand"
	"encoding/hex"
)

type Config struct {
	StrictMode       bool   `json:"strict_mode"`
	AutoScan         bool   `json:"auto_scan"`
	WhitelistedPaths string `json:"whitelisted_paths"`
	APIKey           string `json:"api_key,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		StrictMode:       false,
		AutoScan:         false,
		WhitelistedPaths: "",
		APIKey:           generateAPIKey(),
	}
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
