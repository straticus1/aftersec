package binaryauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyCacheRejectsCorruptionAndUsesPrivatePermissions(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p, _ := SignPolicy(priv, Policy{Version: 1, ExpiresAt: time.Now().Add(time.Hour), AllowedHashes: []string{"abc"}})
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := SavePolicy(path, p); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	data[len(data)-2] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("expected corrupt policy rejection")
	}
}
