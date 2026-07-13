package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedQuoteVerifierAcceptsBoundEvidenceAndRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewSignedQuoteVerifier(map[string]ed25519.PublicKey{"darwin": publicKey})
	evidence := Evidence{HardwareID: "hw-1", Platform: "darwin", Nonce: make([]byte, 32), PublicKey: []byte("endpoint-key")}
	evidence.Quote = ed25519.Sign(privateKey, QuoteMessage(evidence))
	if err := verifier.Verify(context.Background(), evidence); err != nil {
		t.Fatalf("valid quote rejected: %v", err)
	}
	evidence.HardwareID = "hw-attacker"
	if err := verifier.Verify(context.Background(), evidence); err == nil {
		t.Fatal("tampered identity accepted with original quote")
	}
}

func TestSignedQuoteVerifierRejectsUnknownPlatform(t *testing.T) {
	verifier := NewSignedQuoteVerifier(map[string]ed25519.PublicKey{})
	if err := verifier.Verify(context.Background(), Evidence{Platform: "unknown"}); err == nil {
		t.Fatal("unknown platform accepted")
	}
}

func TestLoadSignedQuoteVerifierRejectsMalformedTrustKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignedQuoteVerifier(map[string]string{"linux": path}); err == nil {
		t.Fatal("malformed attestation trust key accepted")
	}
}

func TestLoadSignedQuoteVerifierLoadsEd25519PEM(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignedQuoteVerifier(map[string]string{"linux": path}); err != nil {
		t.Fatal(err)
	}
}
