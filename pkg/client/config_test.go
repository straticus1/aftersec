package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	os.Setenv("AFTERSEC_MODE", "")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got %v", err)
	}

	if cfg.Mode != ModeStandalone {
		t.Errorf("expected mode %s, got %s", ModeStandalone, cfg.Mode)
	}
	if cfg.Storage.Type != StorageLocal {
		t.Errorf("expected storage %s, got %s", StorageLocal, cfg.Storage.Type)
	}
}

func TestLoadConfig_EnvOverride(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	os.Setenv("AFTERSEC_MODE", string(ModeEnterprise))
	defer os.Setenv("AFTERSEC_MODE", "")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got %v", err)
	}

	if cfg.Mode != ModeEnterprise {
		t.Errorf("expected mode %s, got %s", ModeEnterprise, cfg.Mode)
	}
}

func TestLoadConfig_File(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlData := `
mode: enterprise
storage:
  type: cache
  path: /tmp/cache
server:
  address: "localhost:8443"
`
	if err := os.WriteFile(configPath, []byte(yamlData), 0644); err != nil {
		t.Fatal(err)
	}

	os.Setenv("AFTERSEC_MODE", "")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Mode != ModeEnterprise {
		t.Errorf("expected mode %s, got %s", ModeEnterprise, cfg.Mode)
	}
	if cfg.Server == nil || cfg.Server.Address != "localhost:8443" {
		t.Errorf("expected server address %s, got %v", "localhost:8443", cfg.Server)
	}
}
