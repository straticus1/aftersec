package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func sample(t *testing.T, body []byte) Artifact {
	t.Helper()
	sum := sha256.Sum256(body)
	return Artifact{Name: "aftersec", OS: "darwin", Arch: "arm64", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("agent")
	ca := []byte("ca")
	agent := sample(t, body)
	sum := sha256.Sum256(ca)
	manifest := Manifest{Version: "1", Artifacts: []Artifact{agent, {Name: "management-ca", OS: "darwin", Arch: "arm64", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(ca))}}}
	signed, err := Sign(private, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(public, signed); err != nil {
		t.Fatal(err)
	}
	signed[len(signed)-4] ^= 1
	if _, err = Verify(public, signed); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	if _, err = Sign(private, Manifest{Version: "1", Artifacts: []Artifact{{Name: "curl", OS: "darwin", Arch: "arm64", SHA256: agent.SHA256, Size: 1}}}); err == nil {
		t.Fatal("unexpected artifact name signed")
	}
}

func TestPythonBootstrapInstallsOnlyASignedRelease(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := PublicPEM(public)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	agent := []byte("#!/bin/sh\necho agent\n")
	ca := []byte("management-ca\n")
	files := map[string][]byte{"aftersec": agent, "management-ca": ca}
	var artifacts []Artifact
	artifactDir := filepath.Join(root, "artifacts")
	if err = os.Mkdir(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		if err = os.WriteFile(filepath.Join(artifactDir, digest), body, 0o600); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, Artifact{Name: name, OS: "darwin", Arch: "arm64", SHA256: digest, Size: int64(len(body))})
	}
	signed, err := Sign(private, Manifest{Version: "1", Artifacts: artifacts})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err = os.WriteFile(manifestPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "key.pem")
	if err = os.WriteFile(keyPath, []byte(pemKey), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "bin")
	home := filepath.Join(root, "home")
	script := filepath.Join("..", "..", "deploy", "bootstrap.py")
	cmd := exec.Command("python3", script, "--manifest", manifestPath, "--artifact-dir", artifactDir, "--public-key", keyPath, "--dest", dest, "--tenant", "org-1", "--grpc", "mgmt.example:9090", "--os", "darwin", "--arch", "arm64")
	cmd.Env = append(os.Environ(), "HOME="+home)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	installed, err := os.ReadFile(filepath.Join(dest, "aftersec"))
	if err != nil || string(installed) != string(agent) {
		t.Fatalf("installed agent: %v", err)
	}
	info, err := os.Stat(filepath.Join(home, ".aftersec", "config.yaml"))
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("config mode: %v %+v", err, info)
	}
	sum := sha256.Sum256(agent)
	tampered := filepath.Join(artifactDir, hex.EncodeToString(sum[:]))
	if err = os.WriteFile(tampered, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("python3", script, "--manifest", manifestPath, "--artifact-dir", artifactDir, "--public-key", keyPath, "--dest", filepath.Join(root, "bin2"), "--os", "darwin", "--arch", "arm64")
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(root, "home2"))
	if err = cmd.Run(); err == nil {
		t.Fatal("tampered artifact installed")
	}
}
