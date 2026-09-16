package main

import (
	"aftersec/pkg/client"
	"aftersec/pkg/edr"
	"testing"
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
	handleAuthEvent(edr.ProcessEvent{}, r, nil, nil, nil, nil)
	if r.calls != 1 || r.allow || r.cache {
		t.Fatalf("response: %+v", r)
	}
}

func TestStandaloneAuthAllowsAfterChecks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := &authResponder{}
	cfg := client.DefaultClientConfig()
	cfg.Daemon.BinaryAuth.Enabled = false
	handleAuthEvent(edr.ProcessEvent{}, r, cfg, nil, nil, nil)
	if r.calls != 1 || !r.allow || r.cache {
		t.Fatalf("response: %+v", r)
	}
}

func TestEnterpriseWithoutServerDenies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := client.DefaultClientConfig()
	cfg.Mode = client.ModeEnterprise
	cfg.Daemon.BinaryAuth.Enabled = false
	r := &authResponder{}
	handleAuthEvent(edr.ProcessEvent{}, r, cfg, nil, nil, nil)
	if r.calls != 1 || r.allow {
		t.Fatalf("response: %+v", r)
	}
}
