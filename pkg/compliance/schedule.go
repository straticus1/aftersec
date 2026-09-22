package compliance

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"
)

// Job runs a verified pack and submits signed evidence.
// Threats: unsigned packs and executor failures abort the run; evidence is
// not submitted unless every control completed under the runner contract.
type Job struct {
	PublicKey   ed25519.PublicKey
	EvidenceKey ed25519.PrivateKey
	TenantID    string
	EndpointID  string
	Runner      Runner
	Submit      func(context.Context, SignedEvidence) error
}

func (j Job) Run(ctx context.Context, signed SignedPack, activeVersion uint64, now time.Time) (SignedEvidence, error) {
	if j.Submit == nil || j.TenantID == "" || j.EndpointID == "" {
		return SignedEvidence{}, ErrInvalidPack
	}
	if err := VerifyPack(signed, j.PublicKey, activeVersion, now); err != nil {
		return SignedEvidence{}, err
	}
	results := make([]Result, 0, len(signed.Pack.Controls))
	for _, control := range signed.Pack.Controls {
		result, err := j.Runner.Run(ctx, control)
		if err != nil {
			return SignedEvidence{}, err
		}
		results = append(results, result)
	}
	evidence, err := SignEvidence(EvidenceBundle{
		TenantID:    j.TenantID,
		EndpointID:  j.EndpointID,
		PackVersion: signed.Pack.Version,
		CollectedAt: now,
		Results:     results,
	}, j.EvidenceKey)
	if err != nil {
		return SignedEvidence{}, err
	}
	if err := j.Submit(ctx, evidence); err != nil {
		return SignedEvidence{}, fmt.Errorf("submit compliance evidence: %w", err)
	}
	return evidence, nil
}
