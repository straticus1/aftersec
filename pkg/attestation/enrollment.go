// Package attestation implements fail-closed endpoint enrollment primitives.
//
// Threats: enrollment codes are CSPRNG-generated, stored only as SHA-256
// digests, compared in constant time, scoped to one organization, expiring, and
// single use. Credentials are issued only after an injected platform verifier
// accepts evidence bound to the requested hardware identity. This core does not
// itself prove Secure Enclave or TPM provenance; platform verifiers must do so.
package attestation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrCodeInvalid        = errors.New("enrollment code is invalid")
	ErrAttestationInvalid = errors.New("platform attestation is invalid")
)

type Evidence struct {
	HardwareID string
	Platform   string
	Nonce      []byte
	Quote      []byte
	PublicKey  []byte
}

type Request struct {
	OrganizationID string
	HardwareID     string
	Hostname       string
	Evidence       Evidence
}

type VerifiedIdentity struct {
	OrganizationID string
	HardwareID     string
	Hostname       string
	Platform       string
	PublicKey      []byte
}

type Result struct {
	ClientCertificate []byte
	RefreshToken      string
	RefreshTokenHash  [sha256.Size]byte
}

type Verifier interface {
	Verify(context.Context, Evidence) error
}

type CertificateIssuer interface {
	IssueClientCertificate(context.Context, VerifiedIdentity) ([]byte, error)
}

type CodeStore interface {
	Put(context.Context, string, [sha256.Size]byte, time.Time) error
	Consume(context.Context, string, [sha256.Size]byte, time.Time) error
}

type atomicEnrollmentStore interface {
	Finalize(context.Context, string, [sha256.Size]byte, time.Time, EnrollmentCommit) error
}

type EnrollmentService struct {
	codes    CodeStore
	verifier Verifier
	issuer   CertificateIssuer
	now      func() time.Time
}

func NewEnrollmentService(codes CodeStore, verifier Verifier, issuer CertificateIssuer, now func() time.Time) *EnrollmentService {
	if now == nil {
		now = time.Now
	}
	return &EnrollmentService{codes: codes, verifier: verifier, issuer: issuer, now: now}
}

func randomToken() (string, [sha256.Size]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	return token, sha256.Sum256([]byte(token)), nil
}

func (s *EnrollmentService) MintCode(ctx context.Context, organizationID string, ttl time.Duration) (string, error) {
	if organizationID == "" || ttl <= 0 {
		return "", fmt.Errorf("organization and positive code lifetime are required")
	}
	code, digest, err := randomToken()
	if err != nil {
		return "", fmt.Errorf("generate enrollment code: %w", err)
	}
	if err := s.codes.Put(ctx, organizationID, digest, s.now().Add(ttl)); err != nil {
		return "", fmt.Errorf("store enrollment code: %w", err)
	}
	return code, nil
}

func (s *EnrollmentService) Enroll(ctx context.Context, code string, request Request) (Result, error) {
	if request.OrganizationID == "" || request.HardwareID == "" || code == "" {
		return Result{}, ErrCodeInvalid
	}
	if request.Evidence.HardwareID != request.HardwareID {
		return Result{}, ErrAttestationInvalid
	}
	expectedNonce := sha256.Sum256([]byte(code))
	if subtle.ConstantTimeCompare(request.Evidence.Nonce, expectedNonce[:]) != 1 {
		return Result{}, ErrAttestationInvalid
	}
	if err := s.verifier.Verify(ctx, request.Evidence); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	codeDigest := sha256.Sum256([]byte(code))
	identity := VerifiedIdentity{
		OrganizationID: request.OrganizationID,
		HardwareID:     request.HardwareID,
		Hostname:       request.Hostname,
		Platform:       request.Evidence.Platform,
		PublicKey:      append([]byte(nil), request.Evidence.PublicKey...),
	}
	certificate, err := s.issuer.IssueClientCertificate(ctx, identity)
	if err != nil {
		return Result{}, fmt.Errorf("issue client certificate: %w", err)
	}
	refreshToken, refreshHash, err := randomToken()
	if err != nil {
		return Result{}, fmt.Errorf("generate refresh token: %w", err)
	}
	if store, ok := s.codes.(atomicEnrollmentStore); ok {
		quoteFingerprint := sha256.Sum256(request.Evidence.Quote)
		err = store.Finalize(ctx, request.OrganizationID, codeDigest, s.now(), EnrollmentCommit{
			HardwareID:             request.HardwareID,
			Hostname:               request.Hostname,
			Platform:               request.Evidence.Platform,
			AttestationFingerprint: quoteFingerprint,
			RefreshTokenHash:       refreshHash,
			ClientCertificate:      certificate,
		})
	} else {
		err = s.codes.Consume(ctx, request.OrganizationID, codeDigest, s.now())
	}
	if err != nil {
		if errors.Is(err, ErrCodeInvalid) {
			return Result{}, ErrCodeInvalid
		}
		return Result{}, fmt.Errorf("persist enrollment: %w", err)
	}
	return Result{ClientCertificate: certificate, RefreshToken: refreshToken, RefreshTokenHash: refreshHash}, nil
}

type memoryCode struct {
	organizationID string
	digest         [sha256.Size]byte
	expiresAt      time.Time
	used           bool
}

// MemoryCodeStore is concurrency-safe and useful for tests or a single-process
// development server. Production must use the transactional PostgreSQL store.
type MemoryCodeStore struct {
	mu    sync.Mutex
	codes []memoryCode
}

func NewMemoryCodeStore() *MemoryCodeStore { return &MemoryCodeStore{} }

func (s *MemoryCodeStore) Put(_ context.Context, organizationID string, digest [sha256.Size]byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes = append(s.codes, memoryCode{organizationID: organizationID, digest: digest, expiresAt: expiresAt})
	return nil
}

func (s *MemoryCodeStore) Consume(_ context.Context, organizationID string, digest [sha256.Size]byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.codes {
		code := &s.codes[i]
		digestMatches := subtle.ConstantTimeCompare(code.digest[:], digest[:]) == 1
		organizationMatches := subtle.ConstantTimeCompare([]byte(code.organizationID), []byte(organizationID)) == 1
		if digestMatches && organizationMatches && !code.used && now.Before(code.expiresAt) {
			code.used = true
			return nil
		}
	}
	return ErrCodeInvalid
}
