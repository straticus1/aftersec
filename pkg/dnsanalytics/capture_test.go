package dnsanalytics

import (
	"context"
	"errors"
	"testing"
)

type captureSource struct{ err error }

func (s captureSource) Watch(context.Context, func(Query) error) error { return s.err }

func TestCaptureRequiredSourceFailureIsReturned(t *testing.T) {
	c := NewCapture(true)
	if err := c.Start(context.Background(), captureSource{err: errors.New("dns hook denied")}, func(Query) error { return nil }); err == nil {
		t.Fatal("expected required DNS capture failure")
	}
}

func TestCaptureRejectsUnattributedQuery(t *testing.T) {
	c := NewCapture(true)
	source := captureSource{}
	_ = source
	if err := c.Emit(Query{Domain: "example.com"}, func(Query) error { return nil }); err == nil {
		t.Fatal("expected unattributed DNS query denial")
	}
}
