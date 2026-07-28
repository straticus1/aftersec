package dnsanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type RDAPClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *RDAPClient) RegisteredAt(ctx context.Context, domain string) (time.Time, error) {
	if c == nil || c.Client == nil || c.BaseURL == "" {
		return time.Time{}, fmt.Errorf("RDAP client is not configured")
	}
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return time.Time{}, err
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return time.Time{}, fmt.Errorf("derive registrable domain: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.BaseURL, "/")+"/"+url.PathEscape(registrable), nil)
	if err != nil {
		return time.Time{}, err
	}
	request.Header.Set("Accept", "application/rdap+json")
	response, err := c.Client.Do(request)
	if err != nil {
		return time.Time{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("RDAP status %d", response.StatusCode)
	}
	var body struct {
		Events []struct {
			Action string    `json:"eventAction"`
			Date   time.Time `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil {
		return time.Time{}, fmt.Errorf("decode RDAP response: %w", err)
	}
	for _, event := range body.Events {
		if event.Action == "registration" && !event.Date.IsZero() {
			return event.Date, nil
		}
	}
	return time.Time{}, fmt.Errorf("RDAP registration event missing")
}
