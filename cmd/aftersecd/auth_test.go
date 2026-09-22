package main

import (
	"aftersec/pkg/breakglass"
	"aftersec/pkg/client"
	"aftersec/pkg/edr"
	"path/filepath"
	"testing"
	"time"
)

type authResponder struct {
	calls        int
	allow, cache bool
}

func (r *authResponder) RespondAuth(_ edr.ProcessEvent, allow, cache bool) error {
	r.calls++
	r.allow, r.cache = allow, cache
	return nil
}

func TestAuthPanicDeniesWithoutCaching(t *testing.T) {
	r := &authResponder{}
	handleAuthEvent(edr.ProcessEvent{}, r, nil, nil, nil, nil, nil)
	if r.calls != 1 || r.allow || r.cache {
		t.Fatalf("response: %+v", r)
	}
}

func TestStandaloneAuthAllowsAfterChecks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := &authResponder{}
	cfg := client.DefaultClientConfig()
	cfg.Daemon.BinaryAuth.Enabled = false
	handleAuthEvent(edr.ProcessEvent{}, r, cfg, nil, nil, nil, nil)
	if r.calls != 1 || !r.allow || r.cache {
		t.Fatalf("response: %+v", r)
	}
}

func TestEnterpriseBreakGlassSkipsDetonationDeny(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := client.DefaultClientConfig()
	cfg.Mode = client.ModeEnterprise
	cfg.Daemon.BinaryAuth.Enabled = false
	g, err := breakglass.NewGuard(filepath.Join(t.TempDir(), "bg.state"), cfg.TenantID, "HW-test", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Activate(time.Now().Add(15 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	r := &authResponder{}
	handleAuthEvent(edr.ProcessEvent{}, r, cfg, nil, nil, nil, g)
	if r.calls != 1 || !r.allow {
		t.Fatalf("break-glass should skip missing-server detonation deny: %+v", r)
	}
}

func TestEnterpriseWithoutServerDenies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := client.DefaultClientConfig()
	cfg.Mode = client.ModeEnterprise
	cfg.Daemon.BinaryAuth.Enabled = false
	r := &authResponder{}
	handleAuthEvent(edr.ProcessEvent{}, r, cfg, nil, nil, nil, nil)
	if r.calls != 1 || r.allow {
		t.Fatalf("response: %+v", r)
	}
}
