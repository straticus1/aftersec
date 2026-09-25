package client

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"sync"

	"aftersec/pkg/attestation"
)

// HardwareEvidenceProvider collects a Secure Enclave or TPM quote. It does
// not fall back to an exportable software key.
//
// Threats: enrollment without a hardware quote is refused. The public key
// returned to certificate verification is the key the attester supplied.
type HardwareEvidenceProvider struct {
	mu       sync.Mutex
	attester attestation.HardwareAttester
	public   crypto.PublicKey
	id       string
}

func NewHardwareEvidenceProvider() (*HardwareEvidenceProvider, error) {
	attester, err := attestation.NewPlatformAttester()
	if err != nil || attester == nil {
		return nil, fmt.Errorf("hardware attestation adapter is unavailable")
	}
	return &HardwareEvidenceProvider{attester: attester}, nil
}

func (p *HardwareEvidenceProvider) Platform() string {
	if p == nil || p.attester == nil {
		return ""
	}
	return p.attester.Platform()
}

func (p *HardwareEvidenceProvider) Prepare(ctx context.Context) (string, error) {
	if p == nil || p.attester == nil {
		return "", attestation.ErrHardwareAttestation
	}
	id, publicKey, err := p.attester.EnsureIdentity(ctx)
	if err != nil {
		return "", err
	}
	parsed, err := parseEndpointPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.id = id
	p.public = parsed
	p.mu.Unlock()
	return id, nil
}

func (p *HardwareEvidenceProvider) PublicKey() crypto.PublicKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.public
}

func (p *HardwareEvidenceProvider) Evidence(ctx context.Context, hardwareID string, nonce []byte) (attestation.Evidence, error) {
	if p == nil || p.attester == nil {
		return attestation.Evidence{}, attestation.ErrHardwareAttestation
	}
	p.mu.Lock()
	id := p.id
	p.mu.Unlock()
	if id == "" || hardwareID == "" || id != hardwareID {
		return attestation.Evidence{}, fmt.Errorf("hardware identity does not match the enrollment request")
	}
	evidence, err := attestation.Collect(ctx, p.attester, nonce)
	if err != nil {
		return attestation.Evidence{}, err
	}
	if evidence.HardwareID != hardwareID {
		return attestation.Evidence{}, fmt.Errorf("hardware attestation identity mismatch")
	}
	return evidence, nil
}

func parseEndpointPublicKey(publicKey []byte) (crypto.PublicKey, error) {
	if len(publicKey) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
	}
	key, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("hardware public key is not a certificate key: %w", err)
	}
	return key, nil
}
