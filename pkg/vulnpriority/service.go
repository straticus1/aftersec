// Package vulnpriority ranks endpoint vulnerabilities using exploit and runtime evidence.
//
// Threats: deterministic, bounded ranking prevents stale feeds or bulk input
// from hiding known risk. It does not prove that external feed publishers are
// trustworthy; feed signature verification belongs at ingestion.
package vulnpriority

import (
	"errors"
	"regexp"
	"sort"
	"time"
)

var (
	ErrInvalidFinding = errors.New("invalid vulnerability finding")
	ErrCapacity       = errors.New("vulnerability ranking capacity exceeded")
	cvePattern        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

type Finding struct {
	CVE       string
	Package   string
	CVSS      float64
	InKEV     bool
	EPSS      float64
	Executing bool
	Listening bool
}

type FeedState struct{ UpdatedAt time.Time }

type RankedFinding struct {
	Finding
	Score      float64
	Confidence float64
	FeedStale  bool
	Reasons    []string
}

func Rank(findings []Finding, feed FeedState, now time.Time, capacity int) ([]RankedFinding, error) {
	if capacity <= 0 || len(findings) > capacity {
		return nil, ErrCapacity
	}
	stale := feed.UpdatedAt.IsZero() || now.Sub(feed.UpdatedAt) > 24*time.Hour || feed.UpdatedAt.After(now.Add(5*time.Minute))
	out := make([]RankedFinding, 0, len(findings))
	for _, finding := range findings {
		if !cvePattern.MatchString(finding.CVE) || finding.Package == "" || finding.CVSS < 0 || finding.CVSS > 10 || finding.EPSS < 0 || finding.EPSS > 1 {
			return nil, ErrInvalidFinding
		}
		r := RankedFinding{Finding: finding, Score: finding.CVSS, Confidence: 1, FeedStale: stale}
		if finding.InKEV {
			r.Score += 10
			r.Reasons = append(r.Reasons, "known exploited vulnerability")
		}
		if finding.EPSS > 0 {
			r.Score += finding.EPSS * 5
			r.Reasons = append(r.Reasons, "exploit probability")
		}
		if finding.Executing {
			r.Score += 4
			r.Reasons = append(r.Reasons, "vulnerable binary executing")
		}
		if finding.Listening {
			r.Score += 5
			r.Reasons = append(r.Reasons, "network exposed")
		}
		if stale {
			r.Confidence = .6
			r.Reasons = append(r.Reasons, "exploit feed stale")
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].CVE < out[j].CVE
		}
		return out[i].Score > out[j].Score
	})
	return out, nil
}
