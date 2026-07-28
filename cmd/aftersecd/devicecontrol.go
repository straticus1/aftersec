package main

import (
	"context"
	"encoding/json"
	"fmt"

	"aftersec/pkg/devicecontrol"
)

type deviceDecisionRecorder struct {
	logger dnsTelemetryLogger
}

func (r deviceDecisionRecorder) RecordDeviceDecision(
	_ context.Context, device devicecontrol.Device, access devicecontrol.Access, decisionErr error,
) error {
	if r.logger == nil {
		return fmt.Errorf("device decision logger unavailable")
	}
	details, err := json.Marshal(map[string]any{
		"device": device, "access": access, "policy_error": errorString(decisionErr),
	})
	if err != nil {
		return err
	}
	severity := "info"
	if access == devicecontrol.Deny || decisionErr != nil {
		severity = "high"
	}
	return r.logger.LogTelemetryEvent("device_control", "removable_media_decision", severity, string(details))
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
