package vulnpriority

import (
	"errors"
	"testing"
	"time"
)

func TestRankPrioritizesKnownExploitedRunningListener(t *testing.T) {
	now := time.Unix(1000, 0)
	items := []Finding{
		{CVE: "CVE-2025-0001", Package: "idle", CVSS: 9.8},
		{CVE: "CVE-2025-0002", Package: "server", CVSS: 7.0, InKEV: true, EPSS: .8, Executing: true, Listening: true},
	}
	ranked, err := Rank(items, FeedState{UpdatedAt: now}, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if ranked[0].CVE != "CVE-2025-0002" || len(ranked[0].Reasons) < 3 {
		t.Fatalf("ranked = %+v", ranked)
	}
}

func TestRankRejectsMalformedCVE(t *testing.T) {
	_, err := Rank([]Finding{{CVE: "not-a-cve", Package: "x"}}, FeedState{UpdatedAt: time.Now()}, time.Now(), 10)
	if !errors.Is(err, ErrInvalidFinding) {
		t.Fatalf("Rank() error = %v", err)
	}
}

func TestRankMarksStaleFeedWithoutErasingRisk(t *testing.T) {
	now := time.Unix(1000000, 0)
	ranked, err := Rank([]Finding{{CVE: "CVE-2025-0001", Package: "x", CVSS: 8}}, FeedState{UpdatedAt: now.Add(-72 * time.Hour)}, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 1 || !ranked[0].FeedStale || ranked[0].Score == 0 || ranked[0].Confidence >= 1 {
		t.Fatalf("ranked = %+v", ranked)
	}
}

func TestRankFailsClosedOverCapacity(t *testing.T) {
	_, err := Rank([]Finding{{CVE: "CVE-2025-0001", Package: "a"}, {CVE: "CVE-2025-0002", Package: "b"}}, FeedState{UpdatedAt: time.Now()}, time.Now(), 1)
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("Rank() error = %v", err)
	}
}
