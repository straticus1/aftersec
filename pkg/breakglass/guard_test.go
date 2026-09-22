package breakglass

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDurationBounds(t *testing.T) {
	if _, err := ParseDuration(""); !errors.Is(err, ErrInvalidOverride) {
		t.Fatal(err)
	}
	if _, err := ParseDuration("30s"); !errors.Is(err, ErrInvalidOverride) {
		t.Fatal(err)
	}
	if _, err := ParseDuration("5h"); !errors.Is(err, ErrInvalidOverride) {
		t.Fatal(err)
	}
	d, err := ParseDuration("15m")
	if err != nil || d != 15*time.Minute {
		t.Fatalf("%v %v", d, err)
	}
}

func TestGuardActivateStatusEndAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := now
	g, err := NewGuard(filepath.Join(t.TempDir(), "breakglass.state"), "t1", "ep1", func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if g.RelaxesPolicy() {
		t.Fatal("idle")
	}
	if err := g.Activate(clock.Add(15 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !g.RelaxesPolicy() {
		t.Fatal("active")
	}
	if err := g.Activate(clock.Add(20 * time.Minute)); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("stack: %v", err)
	}
	clock = clock.Add(16 * time.Minute)
	if g.RelaxesPolicy() {
		t.Fatal("expired window still active")
	}
	if err := g.Activate(clock.Add(15 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := g.End(); err != nil {
		t.Fatal(err)
	}
	if g.RelaxesPolicy() {
		t.Fatal("ended")
	}
}

func TestGuardRejectsTamperedState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.state")
	now := time.Unix(1_700_000_000, 0)
	g, err := NewGuard(path, "t1", "ep1", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Activate(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	st := env["state"].(map[string]any)
	st["tenant_id"] = "other"
	env["state"] = st
	tampered, _ := json.Marshal(env)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewGuard(path, "t1", "ep1", func() time.Time { return now })
	if !errors.Is(err, ErrInvalidOverride) {
		t.Fatalf("tamper: %v", err)
	}
}

func TestNilGuardFailsClosed(t *testing.T) {
	var g *Guard
	if g.RelaxesPolicy() {
		t.Fatal("nil relaxed")
	}
	if err := g.Activate(time.Now().Add(time.Hour)); !errors.Is(err, ErrInvalidOverride) {
		t.Fatal(err)
	}
}
