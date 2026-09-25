package attestation

import (
	"context"
	"errors"
	"testing"
)

type stubAttester struct {
	platform string
	id       string
	pub      []byte
	quote    []byte
	err      error
}

func (s stubAttester) Platform() string { return s.platform }
func (s stubAttester) EnsureIdentity(context.Context) (string, []byte, error) {
	if s.err != nil {
		return "", nil, s.err
	}
	return s.id, s.pub, nil
}
func (s stubAttester) Quote(context.Context, []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.quote, nil
}

func TestCollectRejectsSoftwareSignatureAndMissingHardware(t *testing.T) {
	nonce := make([]byte, 32)
	nonce[0] = 7
	if _, err := Collect(context.Background(), nil, nonce); !errors.Is(err, ErrHardwareAttestation) {
		t.Fatalf("nil attester: %v", err)
	}
	software := stubAttester{platform: "secure-enclave", id: "hw", pub: []byte{1}, quote: make([]byte, 64)}
	if _, err := Collect(context.Background(), software, nonce); !errors.Is(err, ErrHardwareAttestation) {
		t.Fatalf("software quote: %v", err)
	}
	if _, err := Collect(context.Background(), stubAttester{err: errors.New("no device")}, nonce); !errors.Is(err, ErrHardwareAttestation) {
		t.Fatal("device error was replaced")
	}
	quote := make([]byte, 128)
	quote[0] = 9
	got, err := Collect(context.Background(), stubAttester{platform: "secure-enclave", id: "hw", pub: []byte{1, 2}, quote: quote}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != "secure-enclave" || got.HardwareID != "hw" || len(got.Quote) != 128 || got.Quote[0] != 9 {
		t.Fatalf("%+v", got)
	}
	if _, err := Collect(context.Background(), stubAttester{platform: "secure-enclave", id: "hw", pub: []byte{1}, quote: quote}, nonce[:16]); err == nil {
		t.Fatal("short nonce accepted")
	}
}
