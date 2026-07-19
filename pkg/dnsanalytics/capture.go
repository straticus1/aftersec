package dnsanalytics

import (
	"context"
	"fmt"
)

type Source interface {
	Watch(context.Context, func(Query) error) error
}

type Capture struct{ required bool }

func NewCapture(required bool) *Capture { return &Capture{required: required} }

func (c *Capture) Start(ctx context.Context, source Source, sink func(Query) error) error {
	if c == nil || source == nil || sink == nil {
		if c != nil && c.required {
			return fmt.Errorf("required DNS capture source is not configured")
		}
		return nil
	}
	err := source.Watch(ctx, func(query Query) error { return c.Emit(query, sink) })
	if err != nil && c.required {
		return fmt.Errorf("required DNS capture stopped: %w", err)
	}
	return err
}

func (c *Capture) Emit(query Query, sink func(Query) error) error {
	if query.PID <= 0 || query.Process == "" || len(query.Process) > 4096 || sink == nil {
		return fmt.Errorf("DNS query attribution is required")
	}
	if _, err := NormalizeDomain(query.Domain); err != nil {
		return err
	}
	return sink(query)
}
