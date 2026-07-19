// Package compliance verifies CIS-style control packs and signed evidence.
//
// Threats: unsigned, tampered, rolled-back, expired, or oversized compliance
// inputs are rejected and evidence is tenant/endpoint bound. A malicious check
// binary outside the bounded executor remains an operating-system trust issue.
package compliance

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidSignature = errors.New("invalid compliance signature")
	ErrRollback         = errors.New("compliance pack rollback")
	ErrInvalidPack      = errors.New("invalid compliance pack")
	ErrOutputTooLarge   = errors.New("compliance evidence output too large")
)

const maxPackBytes = 1 << 20

type Control struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Command []string `json:"command"`
}

type Pack struct {
	Version   uint64    `json:"version"`
	Platform  string    `json:"platform"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Controls  []Control `json:"controls"`
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
	if pack.Version == 0 || pack.Platform == "" || len(pack.Controls) == 0 || len(pack.Controls) > 4096 {
		return ErrInvalidPack
	}
	for _, control := range pack.Controls {
		if control.ID == "" || control.Title == "" || len(control.Command) == 0 || len(control.Command) > 32 {
			return ErrInvalidPack
		}
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
	if signed.Pack.Version <= activeVersion {
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

type Executor interface {
	Run(context.Context, []string, int) ([]byte, error)
}

type Runner struct {
	Executor       Executor
	Timeout        time.Duration
	MaxOutputBytes int
}

type Result struct {
	ControlID string `json:"control_id"`
	Passed    bool   `json:"passed"`
	Raw       string `json:"raw"`
}

func (r Runner) Run(ctx context.Context, control Control) (Result, error) {
	if r.Executor == nil || r.Timeout <= 0 || r.MaxOutputBytes <= 0 || control.ID == "" || len(control.Command) == 0 {
		return Result{}, ErrInvalidPack
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	output, err := r.Executor.Run(ctx, append([]string(nil), control.Command...), r.MaxOutputBytes)
	if err != nil {
		return Result{}, fmt.Errorf("run control %s: %w", control.ID, err)
	}
	if len(output) > r.MaxOutputBytes {
		return Result{}, ErrOutputTooLarge
	}
	return Result{ControlID: control.ID, Passed: true, Raw: string(output)}, nil
}

type EvidenceBundle struct {
	TenantID    string    `json:"tenant_id"`
	EndpointID  string    `json:"endpoint_id"`
	PackVersion uint64    `json:"pack_version"`
	CollectedAt time.Time `json:"collected_at"`
	Results     []Result  `json:"results"`
}

type SignedEvidence struct {
	Bundle    EvidenceBundle `json:"bundle"`
	Signature []byte         `json:"signature"`
}

func evidenceBytes(bundle EvidenceBundle) ([]byte, error) {
	if bundle.TenantID == "" || bundle.EndpointID == "" || bundle.PackVersion == 0 || bundle.CollectedAt.IsZero() || len(bundle.Results) == 0 || len(bundle.Results) > 4096 {
		return nil, ErrInvalidPack
	}
	data, err := json.Marshal(bundle)
	if err != nil || len(data) > maxPackBytes {
		return nil, ErrInvalidPack
	}
	return data, nil
}

func SignEvidence(bundle EvidenceBundle, privateKey ed25519.PrivateKey) (SignedEvidence, error) {
	data, err := evidenceBytes(bundle)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return SignedEvidence{}, ErrInvalidPack
	}
	return SignedEvidence{Bundle: bundle, Signature: ed25519.Sign(privateKey, data)}, nil
}

func VerifyEvidence(signed SignedEvidence, publicKey ed25519.PublicKey) error {
	data, err := evidenceBytes(signed.Bundle)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, data, signed.Signature) {
		return ErrInvalidSignature
	}
	return nil
}
