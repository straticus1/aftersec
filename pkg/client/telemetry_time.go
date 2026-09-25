package client

import (
	"fmt"
	"time"
)

// TelemetryUnix reads a stored telemetry timestamp. A missing or unparseable
// value is an error so the server does not record the event at the Unix epoch.
func TelemetryUnix(value any) (int64, error) {
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return 0, fmt.Errorf("telemetry timestamp is empty")
		}
		return typed.Unix(), nil
	case int64:
		if typed <= 0 {
			return 0, fmt.Errorf("telemetry timestamp is empty")
		}
		return typed, nil
	case string:
		return parseTelemetryTime(typed)
	case []byte:
		return parseTelemetryTime(string(typed))
	default:
		return 0, fmt.Errorf("telemetry timestamp has an unsupported type")
	}
}

func parseTelemetryTime(raw string) (int64, error) {
	if raw == "" {
		return 0, fmt.Errorf("telemetry timestamp is empty")
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, raw)
		if err == nil && !parsed.IsZero() {
			return parsed.Unix(), nil
		}
	}
	return 0, fmt.Errorf("telemetry timestamp is not a recognized time")
}
