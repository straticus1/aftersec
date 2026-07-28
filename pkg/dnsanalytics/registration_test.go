package dnsanalytics

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRDAPClientUsesRegistrableDomainAndRegistrationEvent(t *testing.T) {
	client := &RDAPClient{
		BaseURL: "https://rdap.test/domain",
		Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://rdap.test/domain/example.com" {
				t.Fatalf("request URL = %s", request.URL)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"events":[{"eventAction":"registration","eventDate":"2026-07-01T00:00:00Z"}]}`,
				)),
				Header: make(http.Header),
			}, nil
		})},
	}
	got, err := client.RegisteredAt(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("registered at %v, want %v", got, want)
	}
}
