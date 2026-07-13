// Package dnsanalytics provides bounded, process-attributed DNS threat analysis.
package dnsanalytics

import (
	"context"
	"fmt"
	"math"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

type Query struct {
	Domain  string
	PID     int
	Process string
}
type Policy struct{ DGAScoreThreshold float64 }
type Result struct {
	Domain         string
	PID            int
	Process        string
	DGAScore       float64
	Punycode       bool
	KnownMalicious bool
	IntelAvailable bool
	Suspicious     bool
	Reasons        []string
}
type ThreatIntel interface {
	Lookup(context.Context, string) (bool, error)
}
type Detector struct {
	intel  ThreatIntel
	policy Policy
}

func NewDetector(i ThreatIntel, p Policy) *Detector { return &Detector{intel: i, policy: p} }

// NormalizeDomain applies strict IDNA lookup normalization and DNS length rules.
// Threats: malformed labels and Unicode ambiguity are rejected before scoring.
func NormalizeDomain(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(raw)), ".")
	if raw == "" || len(raw) > 253 || strings.Contains(raw, "..") {
		return "", fmt.Errorf("invalid DNS name")
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil || len(ascii) > 253 {
		return "", fmt.Errorf("normalize DNS name")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid DNS label")
		}
	}
	return ascii, nil
}

// Analyze combines deterministic local detection with optional enrichment.
// Threats: enrichment outages never suppress local detections; unattributed queries are rejected.
func (d *Detector) Analyze(ctx context.Context, q Query) (Result, error) {
	if q.PID <= 0 || q.Process == "" || len(q.Process) > 4096 {
		return Result{}, fmt.Errorf("process attribution required")
	}
	domain, err := NormalizeDomain(q.Domain)
	if err != nil {
		return Result{}, err
	}
	r := Result{Domain: domain, PID: q.PID, Process: q.Process, Punycode: strings.Contains(domain, "xn--")}
	r.DGAScore = dgaScore(strings.Split(domain, ".")[0])
	threshold := d.policy.DGAScoreThreshold
	if threshold <= 0 || threshold > 1 {
		threshold = .75
	}
	if r.DGAScore >= threshold {
		r.Suspicious = true
		r.Reasons = append(r.Reasons, "high local DGA score")
	}
	if r.Punycode {
		r.Suspicious = true
		r.Reasons = append(r.Reasons, "punycode/homoglyph risk")
	}
	if d.intel != nil {
		bad, e := d.intel.Lookup(ctx, domain)
		if e == nil {
			r.IntelAvailable = true
			r.KnownMalicious = bad
			if bad {
				r.Suspicious = true
				r.Reasons = append(r.Reasons, "threat intelligence match")
			}
		}
	}
	return r, nil
}
func dgaScore(label string) float64 {
	if len(label) < 6 {
		return 0
	}
	counts := map[rune]float64{}
	digits := 0
	for _, r := range label {
		counts[r]++
		if unicode.IsDigit(r) {
			digits++
		}
	}
	n := float64(len([]rune(label)))
	entropy := 0.0
	for _, c := range counts {
		p := c / n
		entropy -= p * math.Log2(p)
	}
	score := entropy/4.5 + float64(digits)/n*.25
	if score > 1 {
		return 1
	}
	return score
}
