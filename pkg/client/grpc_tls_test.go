package client

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildClientTLSConfigRequiresTrustedCA(t *testing.T) {
	_, err := buildClientTLSConfig(TLSConfig{Cert: "client.crt", Key: "client.key"})
	if err == nil {
		t.Fatal("expected TLS configuration without a CA to fail closed")
	}
}

func TestBuildClientTLSConfigRejectsIncompleteClientIdentity(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := buildClientTLSConfig(TLSConfig{CA: ca, Cert: "client.crt"})
	if err == nil {
		t.Fatal("expected an incomplete certificate/key pair to be rejected")
	}
}

func TestBuildClientTLSConfigRejectsInvalidCA(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := buildClientTLSConfig(TLSConfig{CA: ca})
	if err == nil {
		t.Fatal("expected an invalid CA bundle to be rejected")
	}
}

func TestClientTLSMinimumVersionIsTLS13(t *testing.T) {
	if clientTLSMinimumVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version = %x, want TLS 1.3", clientTLSMinimumVersion)
	}
}
