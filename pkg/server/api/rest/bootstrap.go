package rest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"aftersec/pkg/bootstrap"
)

// Bootstrap serves the one script a new endpoint runs, plus the signed release it installs.
//
// Threats: a missing key, a manifest that does not verify, or an artifact
// whose bytes do not match the signed hash is not served. The script cannot
// be asked to fetch an arbitrary URL.
type Bootstrap struct {
	Public      ed25519.PublicKey
	Manifest    string
	ArtifactDir string
	Script      string
}

func LoadBootstrap(publicPath, manifestPath, artifactDir, scriptPath string) (*Bootstrap, error) {
	if publicPath == "" || manifestPath == "" || artifactDir == "" || scriptPath == "" {
		return nil, fmt.Errorf("bootstrap publisher paths are required")
	}
	raw, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap public key: %w", err)
	}
	public, err := parsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap manifest: %w", err)
	}
	if _, err = bootstrap.Verify(public, manifest); err != nil {
		return nil, err
	}
	info, err := os.Stat(artifactDir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("bootstrap artifact directory is unavailable")
	}
	if _, err = os.Stat(scriptPath); err != nil {
		return nil, fmt.Errorf("bootstrap script is unavailable")
	}
	return &Bootstrap{Public: public, Manifest: manifestPath, ArtifactDir: artifactDir, Script: scriptPath}, nil
}

func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("bootstrap public key is invalid")
	}
	der := block.Bytes
	if len(der) < ed25519.PublicKeySize {
		return nil, fmt.Errorf("bootstrap public key is invalid")
	}
	return ed25519.PublicKey(append([]byte(nil), der[len(der)-ed25519.PublicKeySize:]...)), nil
}

func (b *Bootstrap) ManifestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := os.ReadFile(b.Manifest)
	if err != nil || len(raw) > bootstrap.MaxManifest {
		http.Error(w, "bootstrap manifest is unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err = bootstrap.Verify(b.Public, raw); err != nil {
		http.Error(w, "bootstrap manifest is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (b *Bootstrap) ArtifactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	digest := strings.TrimPrefix(r.URL.Path, "/api/v1/bootstrap/artifacts/")
	if len(digest) != 64 || strings.Contains(digest, "/") || !bootstrapLowerHex(digest) {
		http.Error(w, "bootstrap artifact is unavailable", http.StatusNotFound)
		return
	}
	raw, err := os.ReadFile(b.Manifest)
	if err != nil {
		http.Error(w, "bootstrap artifact is unavailable", http.StatusNotFound)
		return
	}
	manifest, err := bootstrap.Verify(b.Public, raw)
	if err != nil || !manifestHas(manifest, digest) {
		http.Error(w, "bootstrap artifact is unavailable", http.StatusNotFound)
		return
	}
	path := filepath.Join(b.ArtifactDir, digest)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		http.Error(w, "bootstrap artifact is unavailable", http.StatusNotFound)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, "bootstrap artifact is unavailable", http.StatusNotFound)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, file)
}

func (b *Bootstrap) ScriptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	script, err := os.ReadFile(b.Script)
	if err != nil || !strings.Contains(string(script), "AFTERSEC_BOOTSTRAP_PUBLIC_KEY") {
		http.Error(w, "bootstrap script is unavailable", http.StatusServiceUnavailable)
		return
	}
	pemKey, err := bootstrap.PublicPEM(b.Public)
	if err != nil {
		http.Error(w, "bootstrap script is unavailable", http.StatusServiceUnavailable)
		return
	}
	body := strings.Replace(string(script), "AFTERSEC_BOOTSTRAP_PUBLIC_KEY", strings.TrimSpace(pemKey), 1)
	sum := sha256.Sum256([]byte(body))
	fingerprint := hex.EncodeToString(sum[:])
	w.Header().Set("Content-Type", "text/x-python; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Aftersec-Bootstrap-SHA256", fingerprint)
	_, _ = io.WriteString(w, body)
}

func manifestHas(manifest bootstrap.Manifest, digest string) bool {
	for _, artifact := range manifest.Artifacts {
		if artifact.SHA256 == digest {
			return true
		}
	}
	return false
}

func bootstrapLowerHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
