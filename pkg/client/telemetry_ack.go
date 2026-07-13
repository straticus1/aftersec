package client

import "fmt"

// Threats: AcknowledgedTelemetryIDs converts an upstream count into only the
// contiguous local row prefix proven durable upstream. It rejects counts beyond
// the sent batch and rows without stable IDs; it does not authenticate the ack.
func AcknowledgedTelemetryIDs(batch []map[string]any, acknowledged int32) ([]int, error) {
	if acknowledged < 0 || int64(acknowledged) > int64(len(batch)) {
		return nil, fmt.Errorf("invalid telemetry acknowledgment count %d for batch of %d", acknowledged, len(batch))
	}
	ids := make([]int, 0, acknowledged)
	for i := 0; i < int(acknowledged); i++ {
		switch id := batch[i]["id"].(type) {
		case int64:
			ids = append(ids, int(id))
		case int:
			ids = append(ids, id)
		default:
			return nil, fmt.Errorf("acknowledged telemetry row %d has no durable ID", i)
		}
	}
	return ids, nil
}
