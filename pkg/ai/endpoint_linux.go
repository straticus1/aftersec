//go:build linux

package ai

import (
	"context"
	"errors"

	"aftersec/pkg/client"
)

type EndpointAI struct{}

var localAI *EndpointAI

func InitEndpointAI(_ client.EndpointAIConfig) error { return nil }

func Close() {}

func RecordObservation(_, _ string) {}

func TriggerLocalTraining(_ context.Context) error {
	return errors.New("CoreML not available on Linux")
}

func AssessAnomaly(_, _ string) float32 { return 0 }

func Status() string { return "disabled (Linux)" }
