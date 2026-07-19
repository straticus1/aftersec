package response

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

type actionRunner struct {
	calls int
	args  map[string]string
}

func (r *actionRunner) Run(_ context.Context, action Action, args map[string]string) ([]byte, error) {
	r.calls++
	r.args = args
	return []byte(action), nil
}

func TestRemoteActionRejectsWrongEndpointAndReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	token, err := SignActionToken(priv, ActionClaims{ID: "one", TenantID: "tenant", EndpointID: "other", Action: ActionKillProcess, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	runner := &actionRunner{}
	exec := NewActionExecutor(pub, "tenant", "endpoint", runner, 1024, func() time.Time { return now })
	if _, err := exec.Execute(context.Background(), token, nil); err == nil {
		t.Fatal("expected wrong endpoint denial")
	}
	if runner.calls != 0 {
		t.Fatal("runner called for unauthorized action")
	}

	token, _ = SignActionToken(priv, ActionClaims{ID: "two", TenantID: "tenant", EndpointID: "endpoint", Action: ActionKillProcess, ExpiresAt: now.Add(time.Minute)})
	if _, err := exec.Execute(context.Background(), token, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Execute(context.Background(), token, nil); err == nil {
		t.Fatal("expected replay denial")
	}
}

func TestRemoteActionUsesOnlySignedArguments(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	token, err := SignActionToken(priv, ActionClaims{
		ID: "signed-args", TenantID: "tenant", EndpointID: "endpoint",
		Action: ActionKillProcess, ExpiresAt: now.Add(time.Minute),
		Arguments: map[string]string{"pid": "42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &actionRunner{}
	exec := NewActionExecutor(pub, "tenant", "endpoint", runner, 1024, func() time.Time { return now })
	if _, err := exec.Execute(context.Background(), token, map[string]string{"pid": "1"}); err != nil {
		t.Fatal(err)
	}
	if runner.args["pid"] != "42" {
		t.Fatalf("runner args = %v; unsigned caller arguments were accepted", runner.args)
	}
}

func TestRemoteActionRejectsExpiredAndOversizedOutput(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	exec := NewActionExecutor(pub, "tenant", "endpoint", &actionRunner{}, 2, func() time.Time { return now })
	expired, _ := SignActionToken(priv, ActionClaims{ID: "expired", TenantID: "tenant", EndpointID: "endpoint", Action: ActionKillProcess, ExpiresAt: now.Add(-time.Second)})
	if _, err := exec.Execute(context.Background(), expired, nil); err == nil {
		t.Fatal("expected expiry denial")
	}
	valid, _ := SignActionToken(priv, ActionClaims{ID: "large", TenantID: "tenant", EndpointID: "endpoint", Action: ActionKillProcess, ExpiresAt: now.Add(time.Minute)})
	if _, err := exec.Execute(context.Background(), valid, nil); err == nil {
		t.Fatal("expected output limit denial")
	}
}
