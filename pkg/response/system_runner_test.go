package response

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"aftersec/pkg/breakglass"
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

func TestSystemRunnerBreakGlassActivatesWindow(t *testing.T) {
	g, err := breakglass.NewGuard(filepath.Join(t.TempDir(), "bg.state"), "t", "ep", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	r := NewSystemActionRunner(nil, 4096).WithBreakGlass(g)
	if _, err := r.Run(context.Background(), ActionBreakGlass, nil); err == nil {
		t.Fatal("missing duration")
	}
	if _, err := r.Run(context.Background(), ActionBreakGlass, map[string]string{"duration": "15m"}); err != nil {
		t.Fatal(err)
	}
	if !g.RelaxesPolicy() {
		t.Fatal("window not active")
	}
}

func TestSystemRunnerRejectsInvalidKillPID(t *testing.T) {
	r := NewSystemActionRunner(nil, 4096)
	if _, err := r.Run(context.Background(), ActionKillProcess, map[string]string{"pid": "0"}); err == nil {
		t.Fatal("accepted invalid process id")
	}
}
