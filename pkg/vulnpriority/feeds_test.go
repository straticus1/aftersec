package vulnpriority

import (
	"errors"
	"testing"
	"time"
)

func TestParseKEVRejectsStaleMalformedAndEmpty(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	fresh := []byte(`{"dateReleased":"2026-09-22T00:00:00Z","vulnerabilities":[{"cveID":"CVE-2026-1234"}]}`)
	kev, released, err := ParseKEV(fresh, now)
	if err != nil || released.IsZero() || len(kev) != 1 {
		t.Fatalf("fresh: %v %v %v", kev, released, err)
	}
	stale := []byte(`{"dateReleased":"2026-09-01T00:00:00Z","vulnerabilities":[{"cveID":"CVE-2026-1234"}]}`)
	if _, _, err := ParseKEV(stale, now); !errors.Is(err, ErrStaleFeed) {
		t.Fatalf("stale: %v", err)
	}
	if _, _, err := ParseKEV([]byte(`{"dateReleased":"2026-09-22T00:00:00Z","vulnerabilities":[{"cveID":"nope"}]}`), now); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("bad cve: %v", err)
	}
	if _, _, err := ParseKEV(nil, now); !errors.Is(err, ErrInvalidFeed) {
		t.Fatal(err)
	}
}

func TestParseEPSSAndJoin(t *testing.T) {
	epss, err := ParseEPSS([]byte("cve,epss,percentile\nCVE-2026-1234,0.9,0.99\n"))
	if err != nil || epss["CVE-2026-1234"] != 0.9 {
		t.Fatalf("%v %v", epss, err)
	}
	if _, err := ParseEPSS([]byte("cve,epss\nCVE-2026-1234,1.5\n")); !errors.Is(err, ErrInvalidFeed) {
		t.Fatal(err)
	}
	joined := Join([]Finding{{CVE: "CVE-2026-1234", Package: "openssl", CVSS: 9}}, Feeds{
		KEV:  map[string]struct{}{"CVE-2026-1234": {}},
		EPSS: map[string]float64{"CVE-2026-1234": 0.9},
	})
	if !joined[0].InKEV || joined[0].EPSS != 0.9 {
		t.Fatalf("%+v", joined)
	}
}
