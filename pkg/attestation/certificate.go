package attestation

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CAIssuer signs short-lived endpoint certificates with operator-provided CA
// material. Threats: it binds the verified organization/hardware identity and
// attested public key into a client-auth-only certificate. It does not verify
// platform attestation; EnrollmentService must invoke a platform verifier first.
type CAIssuer struct {
	certificate *x509.Certificate
	privateKey  crypto.Signer
	now         func() time.Time
	lifetime    time.Duration
}

func LoadCAIssuer(certFile, keyFile string, now func() time.Time, lifetime time.Duration) (*CAIssuer, error) {
	if certFile == "" || keyFile == "" || lifetime <= 0 {
		return nil, fmt.Errorf("CA certificate, key, and positive certificate lifetime are required")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load enrollment CA: %w", err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse enrollment CA: %w", err)
	}
	if !certificate.IsCA {
		return nil, fmt.Errorf("enrollment certificate is not a CA")
	}
	privateKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("enrollment CA key cannot sign")
	}
	if now == nil {
		now = time.Now
	}
	return &CAIssuer{certificate: certificate, privateKey: privateKey, now: now, lifetime: lifetime}, nil
}

func NewDevelopmentIssuer(now func() time.Time, lifetime time.Duration) (*CAIssuer, []byte, error) {
	if now == nil {
		now = time.Now
	}
	if lifetime <= 0 {
		return nil, nil, fmt.Errorf("positive certificate lifetime is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate development CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	current := now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AfterSec Development Enrollment CA"},
		NotBefore:             current.Add(-time.Minute),
		NotAfter:              current.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create development CA: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse development CA: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &CAIssuer{certificate: certificate, privateKey: privateKey, now: now, lifetime: lifetime}, caPEM, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func (i *CAIssuer) IssueClientCertificate(_ context.Context, identity VerifiedIdentity) ([]byte, error) {
	if identity.OrganizationID == "" || identity.HardwareID == "" {
		return nil, fmt.Errorf("verified organization and hardware identity are required")
	}
	publicKey, err := x509.ParsePKIXPublicKey(identity.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse attested endpoint public key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	current := i.now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   identity.HardwareID,
			Organization: []string{identity.OrganizationID},
		},
		DNSNames:              nonEmptyStrings(identity.Hostname),
		NotBefore:             current,
		NotAfter:              current.Add(i.lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.certificate, publicKey, i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("issue endpoint certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func nonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}
