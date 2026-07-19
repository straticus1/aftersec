package netsensor

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeBackend struct {
	flows []Flow
	err   error
}

func (f fakeBackend) Run(ctx context.Context, emit func(Flow) error) error {
	if f.err != nil {
		return f.err
	}
	for _, flow := range f.flows {
		if err := emit(flow); err != nil {
			return err
		}
	}
	return nil
}

func validFlow() Flow {
	return Flow{
		ProcessID: 42, ProcessName: "curl", UserID: 501,
		LocalAddress: "10.0.0.2", LocalPort: 51000,
		RemoteAddress: "203.0.113.8", RemotePort: 443,
		Protocol: "tcp", BytesSent: 12, BytesReceived: 34,
		StartedAt: time.Unix(100, 0), EndedAt: time.Unix(101, 0),
		Attribution: AttributionExact,
	}
}

func TestFlowValidateRejectsMissingProcessAttribution(t *testing.T) {
	flow := validFlow()
	flow.ProcessID = 0
	if err := flow.Validate(); !errors.Is(err, ErrMissingAttribution) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingAttribution)
	}
}

func TestFlowValidateRejectsOversizedKernelFields(t *testing.T) {
	flow := validFlow()
	flow.ProcessName = string(make([]byte, MaxProcessNameBytes+1))
	if err := flow.Validate(); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidFlow)
	}
}

func TestSensorFailsWhenRequiredBackendCannotAttach(t *testing.T) {
	s := New(fakeBackend{err: errors.New("permission denied")}, true)
	err := s.Run(context.Background(), make(chan Flow, 1))
	if err == nil {
		t.Fatal("required sensor started despite backend attachment failure")
	}
}

func TestSensorFailsClosedOnQueueSaturation(t *testing.T) {
	out := make(chan Flow, 1)
	out <- validFlow()
	s := New(fakeBackend{flows: []Flow{validFlow()}}, true)
	if err := s.Run(context.Background(), out); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("Run() error = %v, want %v", err, ErrQueueFull)
	}
}

func TestSensorRejectsMalformedBackendEvent(t *testing.T) {
	flow := validFlow()
	flow.RemotePort = 0
	s := New(fakeBackend{flows: []Flow{flow}}, true)
	if err := s.Run(context.Background(), make(chan Flow, 1)); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("Run() error = %v, want %v", err, ErrInvalidFlow)
	}
}
