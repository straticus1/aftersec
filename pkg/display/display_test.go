package display

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = uint8(i)
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type staticCamera struct{ frame []byte }

func (c staticCamera) Frame(context.Context) ([]byte, error) { return c.frame, nil }

type gateCamera struct {
	frame   []byte
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gateCamera) Frame(ctx context.Context) ([]byte, error) {
	g.once.Do(func() { close(g.started) })
	select {
	case <-g.release:
		return g.frame, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func startAgent(t *testing.T, camera Capturer, uid int) (*Client, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "asdisp")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	socketPath := filepath.Join(dir, "d.sock")
	ctx, cancel := context.WithCancel(context.Background())
	agent := &Agent{
		Capturer: camera,
		Spool:    filepath.Join(dir, "spool"),
		Peer:     func(*net.UnixConn) (int, error) { return uid, nil },
	}
	errCh := make(chan error, 1)
	go func() { errCh <- agent.Serve(ctx, socketPath) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = os.Stat(socketPath); err != nil {
		cancel()
		os.RemoveAll(dir)
		t.Fatalf("display agent did not listen: %v", <-errCh)
	}
	return NewClient(socketPath), func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Error("display agent did not stop")
		}
		os.RemoveAll(dir)
	}
}

func TestShotRejectsNonRootAndReturnsJPEG(t *testing.T) {
	frame := testJPEG(t, 8, 8)
	client, stop := startAgent(t, staticCamera{frame}, 501)
	if _, err := client.Capture(context.Background(), 0); err == nil {
		stop()
		t.Fatal("non-root capture succeeded")
	}
	stop()

	client, stop = startAgent(t, staticCamera{frame}, 0)
	defer stop()
	got, err := client.Capture(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateJPEG(got); err != nil {
		t.Fatal(err)
	}
	env, err := Envelope(got)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEnvelope(env)
	if err != nil || !bytes.Equal(opened, got) {
		t.Fatalf("envelope: %v", err)
	}
	env[len(env)-8] ^= 0x2
	if _, err = OpenEnvelope(env); err == nil {
		t.Fatal("tampered frame accepted")
	}
	if _, err = OpenEnvelope([]byte("process termination requested")); !errorsIsNotEnvelope(err) {
		t.Fatalf("other output: %v", err)
	}
}

func errorsIsNotEnvelope(err error) bool {
	return err == ErrNotEnvelope
}

func TestRecordIsBoundedAndExclusive(t *testing.T) {
	if _, _, err := FramePlan(0); err == nil {
		t.Fatal("zero duration accepted")
	}
	if _, _, err := FramePlan(61); err == nil {
		t.Fatal("long duration accepted")
	}
	frame := testJPEG(t, 4, 4)
	gate := &gateCamera{frame: frame, started: make(chan struct{}), release: make(chan struct{})}
	client, stop := startAgent(t, gate, 0)
	defer stop()
	first := make(chan error, 1)
	go func() {
		_, err := client.Capture(context.Background(), 1)
		first <- err
	}()
	select {
	case <-gate.started:
	case <-time.After(2 * time.Second):
		t.Fatal("recording did not start")
	}
	if _, err := client.Capture(context.Background(), 1); err == nil || err.Error() != "display recording is already active" {
		t.Fatalf("second recording: %v", err)
	}
	close(gate.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestRecordKeepsFramesAndRejectsBroadSocket(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	frame := testJPEG(t, 6, 6)
	var sleeps int
	sheet, err := Record(context.Background(), staticCamera{frame}, 3, spool, func(context.Context, time.Duration) error {
		sleeps++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sleeps != 2 || ValidateJPEG(sheet) != nil {
		t.Fatalf("sleeps=%d", sleeps)
	}
	matches, err := filepath.Glob(filepath.Join(spool, "record-*", "frame-*.jpg"))
	if err != nil || len(matches) != 3 {
		t.Fatalf("frames: %v %v", matches, err)
	}
	if err = (&Agent{Capturer: staticCamera{frame}}).Serve(context.Background(), "/tmp/aftersec-display.sock"); err == nil {
		t.Fatal("broad socket directory accepted")
	}
	if _, err = NewClient("display.sock").Capture(context.Background(), 0); err == nil {
		t.Fatal("relative socket accepted")
	}
}

func TestOpenEnvelopeRejectsUnknownField(t *testing.T) {
	env, err := Envelope(testJPEG(t, 2, 2))
	if err != nil {
		t.Fatal(err)
	}
	extra := append([]byte{}, env[:len(env)-1]...)
	extra = append(extra, []byte(`,"cmd":"sh"}`)...)
	if _, err = OpenEnvelope(extra); err == nil {
		t.Fatal("extra field accepted")
	}
}
