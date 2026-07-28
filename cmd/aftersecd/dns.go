package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"aftersec/pkg/dnsanalytics"
)

type dnsTelemetryLogger interface {
	LogTelemetryEvent(source, eventType, severity, details string) error
}

func persistDNSQueries(
	ctx context.Context,
	queries <-chan dnsanalytics.Query,
	detector *dnsanalytics.Detector,
	correlator *dnsanalytics.Correlator,
	logger dnsTelemetryLogger,
) error {
	if queries == nil || detector == nil || correlator == nil || logger == nil {
		return fmt.Errorf("DNS detection pipeline is not configured")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case query, ok := <-queries:
			if !ok {
				return nil
			}
			result, err := detector.Analyze(ctx, query)
			if err != nil {
				return fmt.Errorf("analyze DNS query: %w", err)
			}
			details, err := json.Marshal(result)
			if err != nil {
				return fmt.Errorf("encode DNS result: %w", err)
			}
			severity := "info"
			if result.Suspicious {
				severity = "high"
			}
			if err := logger.LogTelemetryEvent("dns_sensor", "process_dns_query", severity, string(details)); err != nil {
				return fmt.Errorf("persist DNS detection: %w", err)
			}
			if _, err := correlator.RecordDNS(dnsanalytics.DNSObservation{
				PID: result.PID, Domain: result.Domain, Suspicious: result.Suspicious, At: time.Now(),
			}); err != nil {
				return fmt.Errorf("record DNS correlation: %w", err)
			}
		}
	}
}
