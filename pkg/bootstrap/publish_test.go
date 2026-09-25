package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeKey(t *testing.T, dir string, mode os.FileMode) (ed25519.PrivateKey, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, "key.pem")
	if err = os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return private, path
}

func TestPublishSignsOnlyTheHashedFiles(t *testing.T) {
	dir := t.TempDir()
	key, keyPath := writeKey(t, dir, 0o600)
	loaded, err := LoadSigningKey(keyPath)
	if err != nil || !loaded.Equal(key) {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "aftersec")
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(bin, []byte("agent-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ca, []byte("ca-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "release")
	if err = Publish(loaded, "1", out, []ReleaseFile{
		{Name: "aftersec", OS: "darwin", Arch: "arm64", Path: bin},
		{Name: "management-ca", OS: "darwin", Arch: "arm64", Path: ca},
	}); err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile(filepath.Join(out, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(publicPEM)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(parsed.(ed25519.PublicKey), signed)
	if err != nil || len(manifest.Artifacts) != 2 {
		t.Fatal(err, manifest)
	}
	stored, err := os.ReadFile(filepath.Join(out, "artifacts", manifest.Artifacts[0].SHA256))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != "agent-bytes" && string(stored) != "ca-bytes" {
		t.Fatalf("stored %q", stored)
	}
	if err = Publish(loaded, "1", out, []ReleaseFile{{Name: "curl", OS: "darwin", Arch: "arm64", Path: bin}}); err == nil {
		t.Fatal("unexpected artifact name published")
	}
}

func TestLoadSigningKeyRejectsAReadableKey(t *testing.T) {
	dir := t.TempDir()
	_, path := writeKey(t, dir, 0o644)
	if _, err := LoadSigningKey(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
}
