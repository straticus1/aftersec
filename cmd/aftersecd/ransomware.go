package main

import (
	"context"
	"encoding/json"
	"fmt"

	"aftersec/pkg/ransomware"
)

type ransomwareTelemetryRecorder struct {
	logger dnsTelemetryLogger
}

func (r ransomwareTelemetryRecorder) Record(_ context.Context, detection ransomware.Detection) error {
	if r.logger == nil {
		return fmt.Errorf("ransomware telemetry logger is unavailable")
	}
	details, err := json.Marshal(detection)
	if err != nil {
		return err
	}
	return r.logger.LogTelemetryEvent("ransomware_shield", "process_suspended", "critical", string(details))
}
