package scanners

import (
	"strings"
	"testing"
	"time"
)

func TestRunProbeMissingBinaryDoesNotPass(t *testing.T) {
	p := RunProbe(time.Second, "aftersec-probe-missing-binary")
	if p.Ran() {
		t.Fatal("missing binary counted as an answer")
	}
	f := probeFailed("SIP", "enabled", p)
	if f.Passed || !strings.Contains(f.CurrentVal, "probe failed") {
		t.Fatalf("%#v", f)
	}
}

func TestRunProbeKeepsExitStatus(t *testing.T) {
	p := RunProbe(time.Second, "sh", "-c", "echo no; exit 1")
	if !p.Ran() || p.Exit != 1 || !strings.Contains(p.Output, "no") {
		t.Fatalf("%#v", p)
	}
}

func TestRunProbeTimesOut(t *testing.T) {
	p := RunProbe(200*time.Millisecond, "sh", "-c", "sleep 5")
	if p.Ran() || !strings.Contains(p.Err.Error(), "timed out") {
		t.Fatalf("%#v", p)
	}
}
