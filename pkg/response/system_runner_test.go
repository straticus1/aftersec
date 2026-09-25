package response

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"path/filepath"
	"testing"
	"time"

	"aftersec/pkg/breakglass"
	"aftersec/pkg/display"
)

type runnerFirewall struct{ applied, removed bool }

func (f *runnerFirewall) Apply(context.Context, ControlEndpoint) error         { f.applied = true; return nil }
func (f *runnerFirewall) VerifyControl(context.Context, ControlEndpoint) error { return nil }
func (f *runnerFirewall) Remove(context.Context) error                         { f.removed = true; return nil }

func TestSystemRunnerAppliesAndReleasesQuarantine(t *testing.T) {
	fw := &runnerFirewall{}
	r := NewSystemActionRunner(NewQuarantineManager(fw), 4096)
	if _, err := r.Run(context.Background(), ActionQuarantine, map[string]string{"host": "control.example", "port": "9090"}); err != nil {
		t.Fatal(err)
	}
	if !fw.applied {
		t.Fatal("quarantine firewall was not applied")
	}
	if _, err := r.Run(context.Background(), ActionReleaseQuarantine, nil); err != nil {
		t.Fatal(err)
	}
	if !fw.removed {
		t.Fatal("quarantine firewall was not removed")
	}
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

type displayStub struct{ seconds int }

func (d *displayStub) Capture(_ context.Context, seconds int) ([]byte, error) {
	d.seconds = seconds
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 40}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestSystemRunnerDisplayRequiresAgentAndWrapsFrame(t *testing.T) {
	r := NewSystemActionRunner(nil, 1<<20)
	if _, err := r.Run(context.Background(), ActionDisplayShot, nil); err == nil {
		t.Fatal("display shot without an agent succeeded")
	}
	stub := &displayStub{}
	out, err := r.WithDisplay(stub).Run(context.Background(), ActionDisplayRecord, map[string]string{"seconds": "15"})
	if err != nil {
		t.Fatal(err)
	}
	if stub.seconds != 15 {
		t.Fatalf("seconds %d", stub.seconds)
	}
	frame, err := display.OpenEnvelope(out)
	if err != nil || len(frame) == 0 {
		t.Fatal(err)
	}
	if _, err = r.Run(context.Background(), ActionDisplayShot, map[string]string{"cmd": "screencapture"}); err == nil {
		t.Fatal("display shot accepted arguments")
	}
	if _, err = r.Run(context.Background(), ActionMarkStolen, nil); err == nil {
		t.Fatal("stolen mark without a camera succeeded")
	}
}
