package threatintel

// Threats: these tests exercise the IP/IOC enrichment decode path, which turns
// an untrusted upstream (DarkAPI.io) response into a ThreatIOC that downstream
// remediation acts on. The invariants:
//   - A well-formed response decodes into the correct flat ThreatIOC structure
//     (type/value/severity present, not nested or mangled).
//   - Malformed or empty enrichment input fails CLOSED: an error is returned
//     and no partial/corrupt ThreatIOC leaks downstream (no false-positive IOC).
//   - A 404 ("not known") yields (nil, nil) — absence of intel must not be
//     turned into a phantom threat.
//   - Malformed enrichment input must not crash the correlation pipeline.
// What they do NOT cover: TLS/pinning to the upstream, response authenticity,
// or rate-limit correctness.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc lets a test intercept the DarkAPI HTTP call without hitting the
// network, returning a canned response body/status.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newStubbedClient(t *testing.T, status int, body string) *DarkAPIClient {
	t.Helper()
	c, err := NewDarkAPIClient("test-key")
	if err != nil {
		t.Fatalf("NewDarkAPIClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	c.httpClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	return c
}

// TestCheckIPAddress_WellFormed_FlatStructure proves a valid enrichment response
// decodes into the expected flat ThreatIOC (no nesting corruption) with the
// fields downstream remediation relies on.
func TestCheckIPAddress_WellFormed_FlatStructure(t *testing.T) {
	body := `{"type":"ip","value":"192.0.2.66","source":"darkapi","severity":"critical","description":"known C2","tags":["c2","cobaltstrike"]}`
	c := newStubbedClient(t, 200, body)

	ioc, err := c.CheckIPAddress(context.Background(), "192.0.2.66")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ioc == nil {
		t.Fatal("expected an IOC for a matched IP, got nil")
	}
	if ioc.Type != "ip" || ioc.Value != "192.0.2.66" {
		t.Errorf("wrong IOC identity: type=%q value=%q", ioc.Type, ioc.Value)
	}
	if ioc.Severity != "critical" {
		t.Errorf("severity not decoded: got %q, want %q", ioc.Severity, "critical")
	}
	if len(ioc.Tags) != 2 {
		t.Errorf("tags not decoded flat: got %v", ioc.Tags)
	}
}

// TestCheckIPAddress_MalformedJSON_FailsClosed proves that a corrupt upstream
// body yields an error and NO partial IOC — malformed enrichment input must not
// produce a phantom/corrupt threat object.
func TestCheckIPAddress_MalformedJSON_FailsClosed(t *testing.T) {
	c := newStubbedClient(t, 200, `{"type":"ip","value":`) // truncated garbage

	ioc, err := c.CheckIPAddress(context.Background(), "192.0.2.66")
	if err == nil {
		t.Fatal("expected decode error on malformed enrichment body, got nil (fail-open)")
	}
	if ioc != nil {
		t.Fatalf("expected nil IOC on malformed input, got %+v", ioc)
	}
}

// TestCheckIPAddress_EmptyBody_FailsClosed proves an empty 200 body is rejected
// rather than yielding a zero-value ThreatIOC.
func TestCheckIPAddress_EmptyBody_FailsClosed(t *testing.T) {
	c := newStubbedClient(t, 200, ``)

	ioc, err := c.CheckIPAddress(context.Background(), "192.0.2.66")
	if err == nil {
		t.Fatal("expected error on empty enrichment body, got nil")
	}
	if ioc != nil {
		t.Fatalf("expected nil IOC on empty body, got %+v", ioc)
	}
}

// TestCheckIPAddress_NotFound_NoPhantomThreat proves a 404 (no intel on this IP)
// returns (nil, nil): absence of data must not be turned into a threat.
func TestCheckIPAddress_NotFound_NoPhantomThreat(t *testing.T) {
	c := newStubbedClient(t, 404, `not found`)

	ioc, err := c.CheckIPAddress(context.Background(), "192.0.2.66")
	if err != nil {
		t.Fatalf("unexpected error on 404: %v", err)
	}
	if ioc != nil {
		t.Fatalf("404 must not synthesize a threat, got %+v", ioc)
	}
}

// TestCorrelateNetworkConnection_MalformedEnrichment_NoCorruption proves the
// correlation pipeline tolerates malformed enrichment input without crashing
// and without emitting a corrupt CorrelatedThreat.
func TestCorrelateNetworkConnection_MalformedEnrichment_NoCorruption(t *testing.T) {
	c := newStubbedClient(t, 200, `{"type":`) // malformed
	tc := NewThreatCorrelator(c)

	threat, err := tc.CorrelateNetworkConnection(context.Background(), "endpoint-1", "192.0.2.66", "")
	if err != nil {
		t.Fatalf("correlation should degrade gracefully on malformed enrichment, got error: %v", err)
	}
	if threat != nil {
		t.Fatalf("malformed enrichment must not yield a threat, got %+v", threat)
	}
}
