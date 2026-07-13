package darkscan

// Threats: scan-service outages must not allow unscanned files to execute.
// This does not cover malicious results returned by a compromised daemon.

import (
	"context"
	"testing"
)

func TestRealTimeScan_DaemonFailureBlocks(t *testing.T) {
	client := &DaemonClient{lastError: "unavailable"}

	blocked, level, err := client.RealTimeScan(context.Background(), "/tmp/untrusted", 1)
	if err == nil {
		t.Fatal("expected scan failure to be surfaced")
	}
	if !blocked {
		t.Fatal("fail-open: file was allowed when the scan daemon was unavailable")
	}
	if level < ThreatLevelHigh {
		t.Fatalf("fail-open: scan failure threat level = %v, want at least %v", level, ThreatLevelHigh)
	}
}
