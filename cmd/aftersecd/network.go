package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

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
			if isKnownDoHConnection(flow) {
				if err := logger.LogTelemetryEvent("dns_sensor", "process_doh_connection", "medium", string(details)); err != nil {
					return fmt.Errorf("persist DoH connection: %w", err)
				}
			}
		}
	}
}

var knownDoHNetworks = []netip.Prefix{
	netip.MustParsePrefix("1.1.1.1/32"),
	netip.MustParsePrefix("1.0.0.1/32"),
	netip.MustParsePrefix("8.8.8.8/32"),
	netip.MustParsePrefix("8.8.4.4/32"),
	netip.MustParsePrefix("9.9.9.9/32"),
	netip.MustParsePrefix("149.112.112.112/32"),
	netip.MustParsePrefix("2606:4700:4700::/48"),
	netip.MustParsePrefix("2001:4860:4860::/48"),
	netip.MustParsePrefix("2620:fe::/48"),
}

func isKnownDoHConnection(flow netsensor.Flow) bool {
	if flow.Protocol != "tcp" || flow.RemotePort != 443 {
		return false
	}
	address, err := netip.ParseAddr(flow.RemoteAddress)
	if err != nil {
		return false
	}
	for _, network := range knownDoHNetworks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}
