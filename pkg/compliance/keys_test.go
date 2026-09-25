package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateKeyRejectsLoosePermissionsAndSymlinks(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.key")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(priv) {
		t.Fatal("loaded key mismatch")
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
}
