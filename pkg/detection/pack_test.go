package detection

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func validPack() Pack {
	return Pack{Version: 2, ExpiresAt: time.Now().Add(time.Hour), Rules: []Rule{{ID: "proc_tmp", YAML: "title: tmp\ndetection:\n  selection:\n    Image: /tmp/a\n"}}}
}

func TestVerifyPackRejectsTamperRollbackExpiryAndEmpty(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()
	signed, err := SignPack(validPack(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPack(signed, pub, 1, now); err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Pack.Rules[0].YAML += " "
	if err := VerifyPack(tampered, pub, 1, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tamper: %v", err)
	}
	if err := VerifyPack(signed, pub, 3, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}
	expired := validPack()
	expired.ExpiresAt = now.Add(-time.Second)
	expiredSigned, err := SignPack(expired, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPack(expiredSigned, pub, 1, now); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := SignPack(Pack{Version: 1}, priv); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("empty: %v", err)
	}
}

func TestStoreKeepsLastValidPackOnFailure(t *testing.T) {
	pub, priv := testKey(t)
	store := NewStore(pub)
	first, err := SignPack(validPack(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(first, time.Now()); err != nil {
		t.Fatal(err)
	}
	bad := first
	bad.Signature[0] ^= 1
	if err := store.Activate(bad, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal(err)
	}
	got, ver, ok := store.Active()
	if !ok || ver != 2 || got.Pack.Rules[0].ID != "proc_tmp" {
		t.Fatalf("store=%+v ver=%d ok=%v", got, ver, ok)
	}
}

func TestUnmarshalPackRejectsOversized(t *testing.T) {
	if _, err := UnmarshalPack(nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatal(err)
	}
	if _, err := UnmarshalPack(make([]byte, maxPackBytes+ed25519.SignatureSize+65)); !errors.Is(err, ErrInvalidPack) {
		t.Fatal(err)
	}
	if _, err := UnmarshalPack([]byte(`{"pack":{"version":1}}`)); !errors.Is(err, ErrInvalidPack) {
		t.Fatal(err)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	_, priv := testKey(t)
	signed, err := SignPack(validPack(), priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalPack(signed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPack(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pack.Version != signed.Pack.Version {
		t.Fatalf("%+v", got)
	}
	if err := json.Unmarshal(raw, &SignedPack{}); err != nil {
		t.Fatal(err)
	}
}
