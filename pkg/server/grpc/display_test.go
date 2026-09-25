package grpcserver

import (
	"bytes"
	"image"
	"image/jpeg"
	"testing"
	"time"

	"aftersec/pkg/display"
	"aftersec/pkg/response"
	"aftersec/pkg/server/displayframes"
)

func TestAcceptDisplayOutputStoresOnlyARequestedFrame(t *testing.T) {
	dir := t.TempDir()
	store, err := displayframes.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{displayFrames: store, pendingDisplay: map[string]displayNote{}}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 40}); err != nil {
		t.Fatal(err)
	}
	env, err := display.Envelope(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	const command = "0123456789abcdef0123456789abcdef"
	if err = s.acceptDisplayOutput("org", "HW-host", command, string(env)); err == nil {
		t.Fatal("unrequested frame stored")
	}
	s.NoteDisplayCommand("HW-host", command, string(response.ActionDisplayShot))
	s.pendingDisplay["HW-host\x00"+command] = displayNote{action: string(response.ActionDisplayShot), at: time.Now().Add(-6 * time.Minute)}
	if err = s.acceptDisplayOutput("org", "HW-host", command, string(env)); err == nil {
		t.Fatal("expired frame stored")
	}
	s.NoteDisplayCommand("HW-host", command, string(response.ActionDisplayShot))
	if err = s.acceptDisplayOutput("org", "HW-host", command, string(env)); err != nil {
		t.Fatal(err)
	}
	f, err := store.Open("org", "HW-host", command)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	s.NoteDisplayCommand("HW-host", command, "kill_process")
	if err = s.acceptDisplayOutput("org", "HW-host", command, string(env)); err == nil {
		t.Fatal("non-display action stored a frame")
	}
}
