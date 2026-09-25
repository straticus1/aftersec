package preserve

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectSkipsSymlinkAndStampsIncident(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("shadow-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hosts"), []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "etc", "passwd")); err != nil {
		t.Fatal(err)
	}
	body, err := Collect(root, Header{IncidentID: "INC-10001", Reason: "breached", Hostname: "eng-01", At: time.Unix(1_700_000_000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("shadow-secret")) {
		t.Fatal("symlink target was packed")
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "preserve-manifest.json" {
		t.Fatal(hdr, err)
	}
	manifest := make([]byte, hdr.Size)
	if _, err = tr.Read(manifest); err != nil && err.Error() != "EOF" {
		// Read may return the bytes plus EOF.
	}
	if !bytes.Contains(manifest, []byte(`"incident_id":"INC-10001"`)) || !bytes.Contains(manifest, []byte(`"skipped":"symlink"`)) {
		t.Fatalf("manifest %s", manifest)
	}
}

func TestCollectRejectsBadMark(t *testing.T) {
	root := t.TempDir()
	if _, err := Collect(root, Header{IncidentID: "../evil", Reason: "lost", Hostname: "h", At: time.Now()}); err == nil {
		t.Fatal("bad incident accepted")
	}
	if _, _, err := ParseMark(map[string]string{"incident_id": "INC-10001", "reason": "lost", "path": "/etc/shadow"}); err == nil {
		t.Fatal("extra argument accepted")
	}
}

func TestClassAndDNSClass(t *testing.T) {
	if class, ok := Class("darkscan", "suspicious_allowed"); !ok || class != ClassSuspicious {
		t.Fatal(class, ok)
	}
	if _, ok := Class("preserve", "preserve_class"); ok {
		t.Fatal("class report reclassified")
	}
	if class, ok := DNSClass("abcdefghijklmnopqrstuvwxyz.example", true, 0.95); !ok || class != ClassExfiltrate {
		t.Fatal(class, ok)
	}
	if class, ok := DNSClass("login.example", true, 0.2); !ok || class != ClassSuspicious {
		t.Fatal(class, ok)
	}
	if _, ok := DNSClass("login.example", false, 0.99); ok {
		t.Fatal("clean dns classified")
	}
}
