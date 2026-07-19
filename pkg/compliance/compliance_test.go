package compliance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyPackRejectsTamperingAndRollback(t *testing.T) {
	pub, priv := keypair(t)
	pack := Pack{Version: 2, Platform: "linux", Controls: []Control{{ID: "1.1", Title: "secure setting", Command: []string{"check"}}}}
	signed, err := SignPack(pack, priv)
	if err != nil {
		t.Fatal(err)
	}
	signed.Pack.Controls[0].Title = "tampered"
	if err := VerifyPack(signed, pub, 0, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("VerifyPack() error = %v", err)
	}
	signed, _ = SignPack(pack, priv)
	if err := VerifyPack(signed, pub, 2, time.Now()); !errors.Is(err, ErrRollback) {
		t.Fatalf("VerifyPack() rollback error = %v", err)
	}
}

type execFunc func(context.Context, []string, int) ([]byte, error)

func (f execFunc) Run(c context.Context, a []string, n int) ([]byte, error) { return f(c, a, n) }

func TestRunnerFailsClosedOnTimeoutAndOversizedEvidence(t *testing.T) {
	r := Runner{Executor: execFunc(func(context.Context, []string, int) ([]byte, error) { return nil, context.DeadlineExceeded }), Timeout: time.Millisecond, MaxOutputBytes: 10}
	if _, err := r.Run(context.Background(), Control{ID: "1", Title: "x", Command: []string{"x"}}); err == nil {
		t.Fatal("expected timeout failure")
	}
	r.Executor = execFunc(func(context.Context, []string, int) ([]byte, error) { return []byte("01234567890"), nil })
	if _, err := r.Run(context.Background(), Control{ID: "1", Title: "x", Command: []string{"x"}}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestEvidenceSignatureRejectsTamperingAndWrongKey(t *testing.T) {
	pub, priv := keypair(t)
	wrong, _ := keypair(t)
	bundle := EvidenceBundle{TenantID: "t1", EndpointID: "h1", PackVersion: 1, CollectedAt: time.Now(), Results: []Result{{ControlID: "1", Passed: true, Raw: "ok"}}}
	signed, err := SignEvidence(bundle, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidence(signed, wrong); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key error = %v", err)
	}
	signed.Bundle.Results[0].Raw = "changed"
	if err := VerifyEvidence(signed, pub); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tamper error = %v", err)
	}
}
