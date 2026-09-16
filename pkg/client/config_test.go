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

func TestDetonationURLRequiresHTTPS(t *testing.T) {
	for _, address := range []string{"http://example.com", "localhost:9090", "https://user:pass@example.com", "https://example.com?q=x", "https://"} {
		if _, err := DetonationURL(&ServerConfig{DetonationAddress: address}); err == nil {
			t.Errorf("accepted %q", address)
		}
	}
	got, err := DetonationURL(&ServerConfig{Address: "localhost:9090", DetonationAddress: "https://example.com/"})
	if err != nil || got != "https://example.com/api/v1/detonate" {
		t.Fatalf("%s, %v", got, err)
	}
}

func TestLoadConfigRejectsCleartextREST(t *testing.T) {
	t.Setenv("AFTERSEC_MODE", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  address: http://example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("accepted cleartext REST")
	}
}
