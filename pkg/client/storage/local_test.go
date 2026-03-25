package storage

import (
	"aftersec/pkg/core"
	"testing"
	"time"
)

func TestLocalManager_SaveAndGetLatest(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewLocalManager(tmpDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	state := &core.SecurityState{
		Timestamp: time.Now(),
		Findings: []core.Finding{
			{
				Category:    "Test",
				Name:        "Test Finding",
				Severity:    core.High,
				Passed:      false,
			},
		},
	}

	if err := mgr.SaveCommit(state); err != nil {
		t.Fatalf("failed to save commit: %v", err)
	}

	latest, err := mgr.GetLatest()
	if err != nil {
		t.Fatalf("failed to get latest: %v", err)
	}
	
	if latest == nil {
		t.Fatal("expected latest state, got nil")
	}

	if len(latest.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(latest.Findings))
	}
	if latest.Findings[0].Name != "Test Finding" {
		t.Errorf("expected finding name 'Test Finding', got %s", latest.Findings[0].Name)
	}
}
