package vulnpriority

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrInvalidFeed = errors.New("invalid vulnerability feed")
	ErrStaleFeed   = errors.New("vulnerability feed is stale")
)

const maxFeedBytes = 8 << 20

type KEVCatalog struct {
	DateReleased     string `json:"dateReleased"`
	Vulnerabilities  []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

type Feeds struct {
	KEV     map[string]struct{}
	EPSS    map[string]float64
	Updated time.Time
}

func ParseKEV(raw []byte, now time.Time) (map[string]struct{}, time.Time, error) {
	if len(raw) == 0 || len(raw) > maxFeedBytes {
		return nil, time.Time{}, ErrInvalidFeed
	}
	var catalog KEVCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, time.Time{}, ErrInvalidFeed
	}
	released, err := time.Parse(time.RFC3339, catalog.DateReleased)
	if err != nil {
		released, err = time.Parse("2006-01-02T15:04:05Z", catalog.DateReleased)
	}
	if err != nil || released.IsZero() {
		return nil, time.Time{}, ErrInvalidFeed
	}
	if now.Sub(released) > 24*time.Hour || released.After(now.Add(5*time.Minute)) {
		return nil, released, ErrStaleFeed
	}
	out := make(map[string]struct{}, len(catalog.Vulnerabilities))
	for _, item := range catalog.Vulnerabilities {
		if !cvePattern.MatchString(item.CVEID) {
			return nil, time.Time{}, ErrInvalidFeed
		}
		out[item.CVEID] = struct{}{}
	}
	if len(out) == 0 {
		return nil, time.Time{}, ErrInvalidFeed
	}
	return out, released, nil
}

func ParseEPSS(raw []byte) (map[string]float64, error) {
	if len(raw) == 0 || len(raw) > maxFeedBytes {
		return nil, ErrInvalidFeed
	}
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	out := make(map[string]float64)
	for {
		rec, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(rec) < 2 {
			return nil, ErrInvalidFeed
		}
		if strings.EqualFold(rec[0], "cve") {
			continue
		}
		if !cvePattern.MatchString(rec[0]) {
			return nil, ErrInvalidFeed
		}
		var score float64
		if _, err := fmt.Sscanf(rec[1], "%f", &score); err != nil || score < 0 || score > 1 {
			return nil, ErrInvalidFeed
		}
		out[rec[0]] = score
	}
	if len(out) == 0 {
		return nil, ErrInvalidFeed
	}
	return out, nil
}

func Join(findings []Finding, feeds Feeds) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if feeds.KEV != nil {
			_, out[i].InKEV = feeds.KEV[out[i].CVE]
		}
		if feeds.EPSS != nil {
			if score, ok := feeds.EPSS[out[i].CVE]; ok {
				out[i].EPSS = score
			}
		}
	}
	return out
}
