package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"aftersec/pkg/core"
)

func TestPostureEvidenceSignsFindingsAndRejectsEmptyOrTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	findings := []core.Finding{{
		Category: "System Capabilities", Name: "SIP", CISBenchmark: "2.12",
		CurrentVal: "enabled", RemediationScript: "csrutil enable", Passed: true,
	}}
	signed, err := PostureEvidence("tenant", "endpoint", at, findings, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidence(signed, pub); err != nil {
		t.Fatal(err)
	}
	if signed.Bundle.PackVersion != PostureSchemaVersion || len(signed.Bundle.Results) != 1 {
		t.Fatalf("%+v", signed.Bundle)
	}
	if strings.Contains(signed.Bundle.Results[0].Raw, "csrutil") || signed.Bundle.Results[0].ControlID != "cis:2.12:System Capabilities/SIP" {
		t.Fatalf("%+v", signed.Bundle.Results[0])
	}
	signed.Bundle.Results[0].Passed = false
	if err := VerifyEvidence(signed, pub); err != ErrInvalidSignature {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := PostureEvidence("tenant", "endpoint", at, nil, priv); err != ErrInvalidPack {
		t.Fatalf("empty: %v", err)
	}
	if _, err := PostureEvidence("", "endpoint", at, findings, priv); err != ErrInvalidPack {
		t.Fatalf("tenant: %v", err)
	}
}
