package stolendevice

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuardRefusesUntilStolenAndUnlocked(t *testing.T) {
	g := NewGuard()
	g.randIntn = func(n int) (int, error) { return 1, nil }
	now := time.Now()
	if _, err := g.Delay(now, true); err == nil {
		t.Fatal("unmarked device was photographed")
	}
	g.Arm()
	if _, err := g.Delay(now, false); err == nil {
		t.Fatal("locked session was photographed")
	}
	delay, err := g.Delay(now, true)
	if err != nil {
		t.Fatal(err)
	}
	if delay < g.MinDelay || delay >= g.MaxDelay {
		t.Fatalf("delay %s", delay)
	}
	g.Mark(now)
	if _, err = g.Delay(now.Add(time.Minute), true); err == nil {
		t.Fatal("photo repeated inside the gap")
	}
	g.hourCount = g.MaxPerHour
	g.last = time.Time{}
	if _, err = g.Delay(now.Add(g.MinGap), true); err == nil {
		t.Fatal("hourly limit was ignored")
	}
	g.Disarm()
	if _, err = g.Delay(now.Add(2*g.MinGap), true); err == nil {
		t.Fatal("cleared device was photographed")
	}
}

func TestRunnerStoresOnlyWhenUnlocked(t *testing.T) {
	dir := t.TempDir()
	var calls int
	frame := tinyJPEG(t)
	runner := &Runner{
		Spool: dir,
		Guard: NewGuard(),
		Camera: func(context.Context) ([]byte, error) {
			calls++
			return frame, nil
		},
		Unlocked: func(context.Context) (bool, error) { return false, nil },
	}
	runner.Guard.MinDelay = 0
	runner.Guard.MaxDelay = 0
	runner.Guard.MinGap = time.Millisecond
	if err := runner.Arm(); err != nil {
		t.Fatal(err)
	}
	runner.Disarm()
	if err := runner.Poll(context.Background(), time.Now()); err == nil {
		t.Fatal("locked poll captured")
	}
	if calls != 0 {
		t.Fatal("camera was used")
	}
	runner.Unlocked = func(context.Context) (bool, error) { return true, nil }
	runner.Guard.Arm()
	if err := runner.Poll(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	id, got, err := runner.Next()
	if err != nil || id == "" || len(got) == 0 {
		t.Fatalf("next: %v %s", err, id)
	}
	if err = runner.Ack(id); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "stolen", id+".jpg")); !os.IsNotExist(err) {
		t.Fatal("acked photo remains")
	}
	if err = runner.Ack("../etc/passwd"); err == nil {
		t.Fatal("path ack accepted")
	}
}

func TestCameraHelperDoesNotDisableTheIndicator(t *testing.T) {
	source, err := os.ReadFile("camera_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, banned := range []string{"LED", "kCMIO", "requestAccess", "setTorchMode"} {
		if strings.Contains(text, banned) {
			t.Fatalf("camera helper contains %s", banned)
		}
	}
}

func tinyJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 40}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
