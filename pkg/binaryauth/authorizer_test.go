package binaryauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestRejectsTamperedAndRollbackPolicy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	a := NewAuthorizer(pub, func() time.Time { return now })
	p1, _ := SignPolicy(priv, Policy{Version: 2, ExpiresAt: now.Add(time.Hour), AllowedHashes: []string{"abc"}})
	if err := a.Activate(p1); err != nil {
		t.Fatal(err)
	}
	p1.Signature[0] ^= 1
	if err := a.Activate(p1); err == nil {
		t.Fatal("expected tampered policy denial")
	}
	old, _ := SignPolicy(priv, Policy{Version: 1, ExpiresAt: now.Add(time.Hour)})
	if err := a.Activate(old); err == nil {
		t.Fatal("expected rollback denial")
	}
}

func TestEnforcesLastPolicyAndExplicitLearnMode(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	a := NewAuthorizer(pub, func() time.Time { return now })
	decision, err := a.Authorize(Executable{SHA256: "new"})
	if err != nil || decision != DecisionLearn {
		t.Fatalf("decision=%s err=%v", decision, err)
	}
	p, _ := SignPolicy(priv, Policy{Version: 1, ExpiresAt: now.Add(time.Hour), AllowedHashes: []string{"good"}})
	if err := a.Activate(p); err != nil {
		t.Fatal(err)
	}
	if d, _ := a.Authorize(Executable{SHA256: "bad"}); d != DecisionDeny {
		t.Fatalf("decision=%s", d)
	}
	if d, _ := a.Authorize(Executable{SHA256: "good"}); d != DecisionAllow {
		t.Fatalf("decision=%s", d)
	}
}

func TestExpiredPolicyDeniesInsteadOfLearning(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	a := NewAuthorizer(pub, func() time.Time { return now })
	p, _ := SignPolicy(priv, Policy{Version: 1, ExpiresAt: now.Add(time.Second), AllowedHashes: []string{"good"}})
	if err := a.Activate(p); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if d, err := a.Authorize(Executable{SHA256: "good"}); err == nil || d != DecisionDeny {
		t.Fatalf("decision=%s err=%v", d, err)
	}
}
