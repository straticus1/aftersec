// Package binaryauth verifies and enforces signed executable policies.
package binaryauth

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionLearn Decision = "learn"
)

type Policy struct {
	Version       uint64    `json:"version"`
	ExpiresAt     time.Time `json:"expires_at"`
	AllowedHashes []string  `json:"allowed_hashes"`
}
type SignedPolicy struct {
	Policy    Policy
	Signature []byte
}
type Executable struct {
	SHA256  string
	TeamID  string
	Package string
}

func SignPolicy(key ed25519.PrivateKey, p Policy) (SignedPolicy, error) {
	b, err := canonicalPolicy(p)
	if err != nil {
		return SignedPolicy{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedPolicy{}, fmt.Errorf("invalid policy signing key")
	}
	return SignedPolicy{Policy: p, Signature: ed25519.Sign(key, b)}, nil
}

type Authorizer struct {
	key    ed25519.PublicKey
	now    func() time.Time
	active *Policy
}

func NewAuthorizer(k ed25519.PublicKey, now func() time.Time) *Authorizer {
	return &Authorizer{key: append(ed25519.PublicKey(nil), k...), now: now}
}

// Activate accepts only valid, fresh, monotonically versioned policies.
// Threats: unsigned, tampered, expired, and rollback policies never replace the last trusted policy.
func (a *Authorizer) Activate(s SignedPolicy) error {
	b, err := canonicalPolicy(s.Policy)
	if err != nil {
		return err
	}
	if len(a.key) != ed25519.PublicKeySize || !ed25519.Verify(a.key, b, s.Signature) {
		return fmt.Errorf("invalid policy signature")
	}
	if a.now == nil || !a.now().Before(s.Policy.ExpiresAt) {
		return fmt.Errorf("policy expired")
	}
	if a.active != nil && s.Policy.Version <= a.active.Version {
		return fmt.Errorf("policy rollback rejected")
	}
	p := s.Policy
	p.AllowedHashes = append([]string(nil), p.AllowedHashes...)
	a.active = &p
	return nil
}
func (a *Authorizer) Authorize(e Executable) (Decision, error) {
	if e.SHA256 == "" || len(e.SHA256) > 128 {
		return DecisionDeny, fmt.Errorf("invalid executable identity")
	}
	if a.active == nil {
		return DecisionLearn, nil
	}
	if a.now == nil || !a.now().Before(a.active.ExpiresAt) {
		return DecisionDeny, fmt.Errorf("last trusted policy expired")
	}
	for _, h := range a.active.AllowedHashes {
		if h == e.SHA256 {
			return DecisionAllow, nil
		}
	}
	return DecisionDeny, nil
}
func canonicalPolicy(p Policy) ([]byte, error) {
	if p.Version == 0 || p.ExpiresAt.IsZero() || len(p.AllowedHashes) > 100000 {
		return nil, fmt.Errorf("invalid policy")
	}
	for _, h := range p.AllowedHashes {
		if h == "" || len(h) > 128 {
			return nil, fmt.Errorf("invalid policy hash")
		}
	}
	return json.Marshal(p)
}
