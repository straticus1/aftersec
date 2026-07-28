package dnsanalytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

type intelFunc func(context.Context, string) (bool, error)

func (f intelFunc) Lookup(c context.Context, d string) (bool, error) { return f(c, d) }

type registrationFunc func(context.Context, string) (time.Time, error)

func (f registrationFunc) RegisteredAt(c context.Context, d string) (time.Time, error) {
	return f(c, d)
}

func TestNormalizeRejectsMalformedAndOversizedDomains(t *testing.T) {
	for _, domain := range []string{"", "bad..example", string(make([]byte, 254))} {
		if _, err := NormalizeDomain(domain); err == nil {
			t.Fatalf("accepted %q", domain)
		}
	}
}
func TestDetectorRequiresProcessAttribution(t *testing.T) {
	d := NewDetector(nil, Policy{DGAScoreThreshold: .7})
	if _, err := d.Analyze(context.Background(), Query{Domain: "example.com"}); err == nil {
		t.Fatal("expected missing attribution denial")
	}
}
func TestThreatIntelOutageDoesNotEraseLocalDGAHit(t *testing.T) {
	d := NewDetector(intelFunc(func(context.Context, string) (bool, error) { return false, errors.New("offline") }), Policy{DGAScoreThreshold: .5})
	r, err := d.Analyze(context.Background(), Query{Domain: "xj3k9q7z2m8v4n6p.com", PID: 42, Process: "/tmp/dropper"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Suspicious || r.IntelAvailable {
		t.Fatalf("result=%+v", r)
	}
}
func TestPunycodeDomainIsFlagged(t *testing.T) {
	d := NewDetector(nil, Policy{DGAScoreThreshold: 1})
	r, err := d.Analyze(context.Background(), Query{Domain: "xn--pple-43d.com", PID: 1, Process: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Suspicious {
		t.Fatalf("result=%+v", r)
	}
}

func TestTrainedNGramModelSeparatesDGAFromBenignLabel(t *testing.T) {
	d := NewDetector(nil, Policy{DGAScoreThreshold: 1})
	benign, err := d.Analyze(context.Background(), Query{Domain: "documentation.example", PID: 1, Process: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	generated, err := d.Analyze(context.Background(), Query{Domain: "xqzv9k2m7p4j.example", PID: 1, Process: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	if generated.NGramScore <= benign.NGramScore {
		t.Fatalf("generated score %.3f <= benign score %.3f", generated.NGramScore, benign.NGramScore)
	}
}

func TestNewRegistrationEnrichmentMarksDomainSuspicious(t *testing.T) {
	registration := registrationFunc(func(context.Context, string) (time.Time, error) {
		return time.Now().Add(-24 * time.Hour), nil
	})
	d := NewDetectorWithRegistration(nil, registration, Policy{
		DGAScoreThreshold: 1,
		NewDomainMaxAge:   7 * 24 * time.Hour,
	})
	result, err := d.Analyze(context.Background(), Query{
		Domain: "ordinary.example", PID: 7, Process: "browser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.RegistrationAvailable || !result.NewlyRegistered || !result.Suspicious {
		t.Fatalf("result=%+v", result)
	}
}

func TestRegistrationOutageDoesNotSuppressLocalResult(t *testing.T) {
	registration := registrationFunc(func(context.Context, string) (time.Time, error) {
		return time.Time{}, errors.New("offline")
	})
	d := NewDetectorWithRegistration(nil, registration, Policy{DGAScoreThreshold: .5})
	result, err := d.Analyze(context.Background(), Query{
		Domain: "xj3k9q7z2m8v4n6p.com", PID: 42, Process: "/tmp/dropper",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Suspicious || result.RegistrationAvailable {
		t.Fatalf("result=%+v", result)
	}
}
