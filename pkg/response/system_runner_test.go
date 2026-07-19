package response

import (
	"context"
	"testing"
)

type runnerFirewall struct{ applied, removed bool }

func (f *runnerFirewall) Apply(context.Context, ControlEndpoint) error { f.applied = true; return nil }
func (f *runnerFirewall) VerifyControl(context.Context, ControlEndpoint) error { return nil }
func (f *runnerFirewall) Remove(context.Context) error { f.removed = true; return nil }

func TestSystemRunnerAppliesAndReleasesQuarantine(t *testing.T) {
	fw := &runnerFirewall{}
	r := NewSystemActionRunner(NewQuarantineManager(fw), 4096)
	if _, err := r.Run(context.Background(), ActionQuarantine, map[string]string{"host": "control.example", "port": "9090"}); err != nil {
		t.Fatal(err)
	}
	if !fw.applied { t.Fatal("quarantine firewall was not applied") }
	if _, err := r.Run(context.Background(), ActionReleaseQuarantine, nil); err != nil { t.Fatal(err) }
	if !fw.removed { t.Fatal("quarantine firewall was not removed") }
}

func TestSystemRunnerRejectsInvalidKillPID(t *testing.T) {
	r := NewSystemActionRunner(nil, 4096)
	if _, err := r.Run(context.Background(), ActionKillProcess, map[string]string{"pid": "0"}); err == nil {
		t.Fatal("accepted invalid process id")
	}
}
