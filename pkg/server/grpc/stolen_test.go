package grpcserver

import (
	"bytes"
	"image"
	"image/jpeg"
	"testing"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/display"
	"aftersec/pkg/server/displayframes"
	"aftersec/pkg/server/stolen"
)

func TestStolenCameraStoresOnlyAMarkedEndpoint(t *testing.T) {
	frames, err := displayframes.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := stolen.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{displayFrames: frames, stolen: reg}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 40}); err != nil {
		t.Fatal(err)
	}
	env, err := display.Envelope(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	event := &grpcapi.ClientEvent{TenantId: "org", HardwareId: "HW-host", EventType: "stolen_camera", Payload: string(env)}
	if summary, stored := s.takeStolenCamera(event); stored || summary != `{"stored":false}` {
		t.Fatalf("unmarked: %s %v", summary, stored)
	}
	if err = reg.Mark("org", "HW-host"); err != nil {
		t.Fatal(err)
	}
	summary, stored := s.takeStolenCamera(event)
	if !stored || bytes.Contains([]byte(summary), buf.Bytes()) {
		t.Fatalf("stored summary leaked or failed: %s", summary)
	}
	if resp, err := s.Heartbeat(t.Context(), &grpcapi.HeartbeatRequest{TenantId: "org", HardwareId: "HW-host", Timestamp: 1_700_000_000}); err != nil || resp.Action != "MARK_STOLEN" {
		t.Fatalf("heartbeat: %v %+v", err, resp)
	}
	if err = reg.Clear("org", "HW-host"); err != nil {
		t.Fatal(err)
	}
	if _, stored = s.takeStolenCamera(event); stored {
		t.Fatal("cleared device stored a photo")
	}
	if resp, err := s.Heartbeat(t.Context(), &grpcapi.HeartbeatRequest{TenantId: "org", HardwareId: "HW-host", Timestamp: 1_700_000_000}); err != nil || resp.Action != "CLEAR_STOLEN" {
		t.Fatalf("clear heartbeat: %v %+v", err, resp)
	}
}
