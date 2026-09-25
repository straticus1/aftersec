package rest

import (
	"bytes"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"testing"

	"aftersec/pkg/server/displayframes"
)

func TestDisplayFrameRequiresOperatorAndTenant(t *testing.T) {
	dir := t.TempDir()
	store, err := displayframes.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 40}); err != nil {
		t.Fatal(err)
	}
	const command = "0123456789abcdef0123456789abcdef"
	if err = store.Save("org-1", "HW-host", command, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	router := &Router{frames: store}
	viewer := authorizedRequest(t, http.MethodGet, "/api/v1/display/frames?endpoint_id=HW-host&command_id="+command, nil, "org-1", "viewer")
	w := httptest.NewRecorder()
	router.handleDisplayFrame(w, viewer)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer status %d", w.Code)
	}
	other := authorizedRequest(t, http.MethodGet, "/api/v1/display/frames?endpoint_id=HW-host&command_id="+command, nil, "org-2", "admin")
	w = httptest.NewRecorder()
	router.handleDisplayFrame(w, other)
	if w.Code != http.StatusNotFound {
		t.Fatalf("other tenant status %d", w.Code)
	}
	op := authorizedRequest(t, http.MethodGet, "/api/v1/display/frames?endpoint_id=HW-host&command_id="+command, nil, "org-1", "security_operator")
	w = httptest.NewRecorder()
	router.handleDisplayFrame(w, op)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/jpeg" || !bytes.Equal(w.Body.Bytes(), buf.Bytes()) {
		t.Fatalf("status %d type %s bytes %d", w.Code, w.Header().Get("Content-Type"), w.Body.Len())
	}
}
