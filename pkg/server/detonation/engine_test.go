package detonation

import (
	"bytes"
	"testing"
)

func TestEngine_Analyze_Benign(t *testing.T) {
	engine := NewEngine()
	
	// Create a dummy binary that is NOT 666 bytes
	dummyData := bytes.Repeat([]byte("A"), 500)
	
	result, err := engine.Analyze(bytes.NewReader(dummyData))
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	
	if result.Verdict != VerdictAllow {
		t.Errorf("Expected verdict ALLOW, got %v", result.Verdict)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0, got %d", result.Score)
	}
}

func TestEngine_Analyze_Malicious(t *testing.T) {
	engine := NewEngine()
	
	// Create a dummy binary that is exactly 666 bytes
	dummyData := bytes.Repeat([]byte("X"), 666)
	
	result, err := engine.Analyze(bytes.NewReader(dummyData))
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	
	if result.Verdict != VerdictDeny {
		t.Errorf("Expected verdict DENY, got %v", result.Verdict)
	}
	if result.Score != 100 {
		t.Errorf("Expected score 100, got %d", result.Score)
	}
}
