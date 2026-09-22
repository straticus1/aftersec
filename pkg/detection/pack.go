// Package detection verifies signed Sigma rule packs before they are compiled.
//
// Threats: unsigned, tampered, rolled-back, expired, empty, or oversized packs
// cannot enter the hunt pipeline. This does not prove a Sigma rule is a useful
// detection, only that the pack was signed by the configured authority.
package detection

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidSignature = errors.New("invalid detection pack signature")
	ErrRollback         = errors.New("detection pack rollback")
	ErrInvalidPack      = errors.New("invalid detection pack")
)

const (
	maxPackBytes = 1 << 20
	maxRules     = 256
	maxYAMLBytes = 64 << 10
)

var ruleIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)

type Rule struct {
	ID   string `json:"id"`
	YAML string `json:"yaml"`
}

type Pack struct {
	Version   uint64    `json:"version"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Rules     []Rule    `json:"rules"`
}

type SignedPack struct {
	Pack      Pack   `json:"pack"`
	Signature []byte `json:"signature"`
}

func packBytes(pack Pack) ([]byte, error) {
	data, err := json.Marshal(pack)
	if err != nil || len(data) > maxPackBytes {
		return nil, ErrInvalidPack
	}
	return data, nil
}

func validatePack(pack Pack) error {
	if pack.Version == 0 || len(pack.Rules) == 0 || len(pack.Rules) > maxRules {
		return ErrInvalidPack
	}
	seen := make(map[string]struct{}, len(pack.Rules))
	for _, rule := range pack.Rules {
		if !ruleIDPattern.MatchString(rule.ID) || rule.YAML == "" || len(rule.YAML) > maxYAMLBytes || !utf8.ValidString(rule.YAML) {
			return ErrInvalidPack
		}
		if _, dup := seen[rule.ID]; dup {
			return ErrInvalidPack
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

func SignPack(pack Pack, privateKey ed25519.PrivateKey) (SignedPack, error) {
	if err := validatePack(pack); err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return SignedPack{}, ErrInvalidPack
	}
	data, err := packBytes(pack)
	if err != nil {
		return SignedPack{}, err
	}
	return SignedPack{Pack: pack, Signature: ed25519.Sign(privateKey, data)}, nil
}

func VerifyPack(signed SignedPack, publicKey ed25519.PublicKey, activeVersion uint64, now time.Time) error {
	if err := validatePack(signed.Pack); err != nil {
		return err
	}
	if signed.Pack.Version < activeVersion {
		return ErrRollback
	}
	if !signed.Pack.ExpiresAt.IsZero() && !now.Before(signed.Pack.ExpiresAt) {
		return ErrInvalidPack
	}
	data, err := packBytes(signed.Pack)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, data, signed.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Store keeps the last verified pack and refuses rollback or verify failures.
type Store struct {
	mu     sync.Mutex
	key    ed25519.PublicKey
	active uint64
	last   SignedPack
}

func NewStore(publicKey ed25519.PublicKey) *Store {
	return &Store{key: publicKey}
}

func (s *Store) Activate(signed SignedPack, now time.Time) error {
	if s == nil {
		return ErrInvalidPack
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := VerifyPack(signed, s.key, s.active, now); err != nil {
		return err
	}
	s.last = signed
	s.active = signed.Pack.Version
	return nil
}

func (s *Store) Active() (SignedPack, uint64, bool) {
	if s == nil {
		return SignedPack{}, 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == 0 {
		return SignedPack{}, 0, false
	}
	return s.last, s.active, true
}

func MarshalPack(signed SignedPack) ([]byte, error) {
	if err := validatePack(signed.Pack); err != nil {
		return nil, err
	}
	data, err := json.Marshal(signed)
	if err != nil || len(data) > maxPackBytes+ed25519.SignatureSize+64 {
		return nil, fmt.Errorf("%w: encode", ErrInvalidPack)
	}
	return data, nil
}

func UnmarshalPack(data []byte) (SignedPack, error) {
	if len(data) == 0 || len(data) > maxPackBytes+ed25519.SignatureSize+64 {
		return SignedPack{}, ErrInvalidPack
	}
	var signed SignedPack
	if err := json.Unmarshal(data, &signed); err != nil {
		return SignedPack{}, ErrInvalidPack
	}
	if err := validatePack(signed.Pack); err != nil {
		return SignedPack{}, err
	}
	return signed, nil
}
