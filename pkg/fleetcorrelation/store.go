package fleetcorrelation

import (
	"context"
	"errors"
	"sync"
)

var ErrPersist = errors.New("fleet alert persistence failed")

type Sink interface {
	Persist(context.Context, Alert) error
}

type MemorySink struct {
	mu     sync.Mutex
	alerts []Alert
	fail   error
}

func (s *MemorySink) Persist(_ context.Context, alert Alert) error {
	if s == nil {
		return ErrPersist
	}
	if s.fail != nil {
		return s.fail
	}
	if alert.TenantID == "" || alert.Kind == "" || alert.Value == "" || len(alert.Endpoints) < 2 {
		return ErrInvalidEvent
	}
	s.mu.Lock()
	s.alerts = append(s.alerts, alert)
	s.mu.Unlock()
	return nil
}

func (s *MemorySink) Alerts(tenantID string) []Alert {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		if alert.TenantID == tenantID {
			out = append(out, alert)
		}
	}
	return out
}

func (e *Engine) RecordAndPersist(ctx context.Context, event Event, sink Sink) (*Alert, error) {
	alert, err := e.Record(event)
	if err != nil {
		return nil, err
	}
	if alert == nil {
		return nil, nil
	}
	if sink == nil {
		return nil, ErrPersist
	}
	if err := sink.Persist(ctx, *alert); err != nil {
		return nil, err
	}
	return alert, nil
}
