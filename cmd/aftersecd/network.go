package main

import (
	"context"
	"encoding/json"
	"fmt"

	"aftersec/pkg/netsensor"
)

type networkTelemetryLogger interface {
	LogTelemetryEvent(source, eventType, severity, details string) error
}

// persistNetworkFlows durably hands normalized flow data to the configured
// storage manager. Threats: serialization or persistence failures stop the
// pipeline so callers can fail a required sensor instead of dropping evidence.
func persistNetworkFlows(ctx context.Context, flows <-chan netsensor.Flow, logger networkTelemetryLogger) error {
	if flows == nil || logger == nil {
		return fmt.Errorf("network flow channel and telemetry logger are required")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case flow, ok := <-flows:
			if !ok {
				return nil
			}
			if err := flow.Validate(); err != nil {
				return err
			}
			details, err := json.Marshal(flow)
			if err != nil {
				return fmt.Errorf("encode network flow: %w", err)
			}
			if err := logger.LogTelemetryEvent("network_sensor", "process_flow", "info", string(details)); err != nil {
				return fmt.Errorf("persist network flow: %w", err)
			}
		}
	}
}
