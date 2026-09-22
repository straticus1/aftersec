package compliance

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"
)

func TestJobRunRejectsUnsignedAndExecutorFailure(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := SignPack(Pack{Version: 1, Platform: "darwin", Controls: []Control{{ID: "c1", Title: "t", Command: []string{os.Args[0], "-test.run=^TestControlHelper$", "--", "pass"}}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	submitted := 0
	job := Job{
		PublicKey: pub, EvidenceKey: priv, TenantID: "t", EndpointID: "e",
		Runner: Runner{Executor: CommandExecutor{}, Timeout: 2 * time.Second, MaxOutputBytes: 64},
		Submit: func(context.Context, SignedEvidence) error { submitted++; return nil },
	}
	t.Setenv("AFTERSEC_CONTROL_HELPER", "1")
	if _, err := job.Run(context.Background(), pack, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if submitted != 1 {
		t.Fatalf("submitted=%d", submitted)
	}
	bad := pack
	bad.Signature[0] ^= 1
	if _, err := job.Run(context.Background(), bad, 1, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("unsigned: %v", err)
	}
	failing := job
	failing.Submit = func(context.Context, SignedEvidence) error { return errors.New("sink down") }
	if _, err := failing.Run(context.Background(), pack, 1, time.Now()); err == nil {
		t.Fatal("expected submit failure")
	}
}
