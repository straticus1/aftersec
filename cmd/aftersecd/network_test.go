package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"aftersec/pkg/netsensor"
)

type flowLogger struct {
	count int
	err   error
}

func (l *flowLogger) LogTelemetryEvent(_, _, _, _ string) error {
	l.count++
	return l.err
}

func attributedFlow() netsensor.Flow {
	return netsensor.Flow{
		ProcessID: 42, ProcessName: "curl", UserID: 501,
		LocalAddress: "10.0.0.2", LocalPort: 51000,
		RemoteAddress: "203.0.113.8", RemotePort: 443,
		Protocol: "tcp", StartedAt: time.Unix(100, 0), EndedAt: time.Unix(101, 0),
		Attribution: netsensor.AttributionExact,
	}
}

func TestPersistNetworkFlowsStoresNormalizedTelemetry(t *testing.T) {
	flows := make(chan netsensor.Flow, 1)
	flows <- attributedFlow()
	close(flows)
	logger := &flowLogger{}
	if err := persistNetworkFlows(context.Background(), flows, logger); err != nil {
		t.Fatal(err)
	}
	if logger.count != 1 {
		t.Fatalf("stored %d flows, want 1", logger.count)
	}
}

func TestKnownDoHConnectionIsClassified(t *testing.T) {
	flow := attributedFlow()
	flow.RemoteAddress = "1.1.1.1"
	flow.RemotePort = 443
	if !isKnownDoHConnection(flow) {
		t.Fatal("expected known encrypted DNS resolver connection")
	}
}

func TestPersistNetworkFlowsRecordsKnownDoHObservation(t *testing.T) {
	flow := attributedFlow()
	flow.RemoteAddress = "1.1.1.1"
	flows := make(chan netsensor.Flow, 1)
	flows <- flow
	close(flows)
	logger := &flowLogger{}
	if err := persistNetworkFlows(context.Background(), flows, logger); err != nil {
		t.Fatal(err)
	}
	if logger.count != 2 {
		t.Fatalf("stored %d events, want flow and DoH observation", logger.count)
	}
}

func TestPersistNetworkFlowsSurfacesStorageFailure(t *testing.T) {
	flows := make(chan netsensor.Flow, 1)
	flows <- attributedFlow()
	logger := &flowLogger{err: errors.New("disk full")}
	if err := persistNetworkFlows(context.Background(), flows, logger); err == nil {
		t.Fatal("expected storage failure")
	}
}
