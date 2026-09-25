package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapSignDoesNotOpenLocalStorage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "aftersec")
	if err = os.WriteFile(bin, []byte("agent-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "release")
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{
		"bootstrap", "sign",
		"--key", keyPath,
		"--version", "1",
		"--os", "darwin",
		"--arch", "arm64",
		"--out", out,
		"--file", "aftersec=" + bin,
	})
	if err = rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(out, "public.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(home, ".aftersec")); !os.IsNotExist(err) {
		t.Fatalf("bootstrap sign opened local storage: %v", err)
	}
}
