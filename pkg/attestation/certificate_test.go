package attestation

// Threats: enrollment certificates must be short lived, signed by the configured
// CA, and bound to the verified endpoint key and identity. Production loading
// must reject absent or mismatched trust material.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"
)

func TestDevelopmentIssuerCreatesVerifiableShortLivedClientCertificate(t *testing.T) {
	now := time.Unix(1000, 0)
	issuer, caPEM, err := NewDevelopmentIssuer(func() time.Time { return now }, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := issuer.IssueClientCertificate(context.Background(), VerifiedIdentity{
		OrganizationID: "org-1", HardwareID: "hw-1", Hostname: "host-1", PublicKey: publicDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now.Add(time.Minute)}); err != nil {
		t.Fatalf("verify client certificate: %v", err)
	}
	if cert.Subject.CommonName != "hw-1" || cert.Subject.Organization[0] != "org-1" {
		t.Fatalf("certificate identity = %#v", cert.Subject)
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 15*time.Minute {
		t.Fatalf("certificate lifetime = %s", cert.NotAfter.Sub(cert.NotBefore))
	}
	issuedKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !issuedKey.Equal(publicKey) {
		t.Fatal("certificate was not bound to endpoint public key")
	}
}

func TestLoadCAIssuerFailsClosedWithoutTrustMaterial(t *testing.T) {
	_, err := LoadCAIssuer(filepath.Join(t.TempDir(), "missing.crt"), filepath.Join(t.TempDir(), "missing.key"), time.Now, time.Hour)
	if err == nil {
		t.Fatal("production CA issuer accepted missing trust material")
	}
}

func TestIssuerRejectsInvalidEndpointPublicKey(t *testing.T) {
	issuer, _, err := NewDevelopmentIssuer(time.Now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.IssueClientCertificate(context.Background(), VerifiedIdentity{
		OrganizationID: "org-1", HardwareID: "hw-1", PublicKey: []byte("not-a-key"),
	}); err == nil {
		t.Fatal("issuer accepted malformed endpoint public key")
	}
}
