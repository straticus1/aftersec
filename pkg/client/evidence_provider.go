package client

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"fmt"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/attestation"
)

// EvidenceProvider owns or references the endpoint key and returns platform
// evidence bound to a server-derived nonce. Production implementations must keep
// private key material non-exportable in Secure Enclave or TPM hardware.
type EvidenceProvider interface {
	Platform() string
	PublicKey() crypto.PublicKey
	Evidence(context.Context, string, []byte) (attestation.Evidence, error)
}

type DevelopmentEvidenceProvider struct {
	platform              string
	attestationPrivateKey ed25519.PrivateKey
	endpointPublicKey     ed25519.PublicKey
	endpointPrivateKey    ed25519.PrivateKey
}

// NewDevelopmentEvidenceProvider creates an exportable software-key provider
// only when development mode is explicitly selected.
func NewDevelopmentEvidenceProvider(mode, platform string, attestationPrivateKey ed25519.PrivateKey) (*DevelopmentEvidenceProvider, error) {
	if mode != "development" {
		return nil, fmt.Errorf("software evidence provider is development-only")
	}
	if platform != "darwin" && platform != "linux" {
		return nil, fmt.Errorf("unsupported development attestation platform")
	}
	if len(attestationPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid development attestation private key")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate development endpoint key: %w", err)
	}
	return &DevelopmentEvidenceProvider{
		platform: platform, attestationPrivateKey: append(ed25519.PrivateKey(nil), attestationPrivateKey...),
		endpointPublicKey: publicKey, endpointPrivateKey: privateKey,
	}, nil
}

func (p *DevelopmentEvidenceProvider) Platform() string { return p.platform }

func (p *DevelopmentEvidenceProvider) PublicKey() crypto.PublicKey {
	return append(ed25519.PublicKey(nil), p.endpointPublicKey...)
}

func (p *DevelopmentEvidenceProvider) Evidence(ctx context.Context, hardwareID string, nonce []byte) (attestation.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return attestation.Evidence{}, err
	}
	if hardwareID == "" || len(nonce) != sha256.Size {
		return attestation.Evidence{}, fmt.Errorf("hardware ID and 32-byte attestation nonce are required")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(p.endpointPublicKey)
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("marshal endpoint public key: %w", err)
	}
	evidence := attestation.Evidence{
		HardwareID: hardwareID,
		Platform:   p.platform,
		Nonce:      append([]byte(nil), nonce...),
		PublicKey:  publicDER,
	}
	evidence.Quote = ed25519.Sign(p.attestationPrivateKey, attestation.QuoteMessage(evidence))
	return evidence, nil
}

type EnrollmentDetails struct {
	OrganizationID string
	EnrollmentCode string
	HardwareID     string
	Hostname       string
	OSVersion      string
	AgentVersion   string
}

// BuildAttestedEnrollRequest creates the complete wire request and verifies the
// provider returned evidence for the exact code-bound nonce and hardware ID.
func BuildAttestedEnrollRequest(ctx context.Context, provider EvidenceProvider, details EnrollmentDetails) (*grpcapi.EnrollRequest, error) {
	if provider == nil || details.OrganizationID == "" || details.EnrollmentCode == "" || details.HardwareID == "" {
		return nil, fmt.Errorf("provider, organization, enrollment code, and hardware ID are required")
	}
	nonce := sha256.Sum256([]byte(details.EnrollmentCode))
	evidence, err := provider.Evidence(ctx, details.HardwareID, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("collect enrollment evidence: %w", err)
	}
	if evidence.HardwareID != details.HardwareID || evidence.Platform != provider.Platform() ||
		subtle.ConstantTimeCompare(evidence.Nonce, nonce[:]) != 1 {
		return nil, fmt.Errorf("evidence provider returned mismatched identity or nonce")
	}
	return &grpcapi.EnrollRequest{
		HardwareId:       details.HardwareID,
		Hostname:         details.Hostname,
		OsVersion:        details.OSVersion,
		AgentVersion:     details.AgentVersion,
		OrganizationId:   details.OrganizationID,
		EnrollmentCode:   details.EnrollmentCode,
		Platform:         evidence.Platform,
		AttestationNonce: evidence.Nonce,
		AttestationQuote: evidence.Quote,
		PublicKey:        evidence.PublicKey,
	}, nil
}
