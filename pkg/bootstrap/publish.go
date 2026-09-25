package bootstrap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Threats: the signing key must be a regular, unencrypted PKCS#8 Ed25519 file
// that is not group- or world-readable. A symlink source, an unknown artifact
// name, or a file larger than the bootstrap cap is rejected. The private key
// is not copied into the output directory.

type ReleaseFile struct {
	Name string
	OS   string
	Arch string
	Path string
}

// LoadSigningKey reads the offline release key.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap signing key is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() == 0 || info.Size() > 16<<10 {
		return nil, fmt.Errorf("bootstrap signing key is unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 16<<10 {
		return nil, fmt.Errorf("bootstrap signing key is unavailable")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("bootstrap signing key is unavailable")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bootstrap signing key is unavailable")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bootstrap signing key is unavailable")
	}
	return key, nil
}

// Publish hashes each file, writes it under its digest name, and signs the manifest.
func Publish(key ed25519.PrivateKey, version, outDir string, files []ReleaseFile) error {
	if len(key) != ed25519.PrivateKeySize || version == "" || outDir == "" || len(files) == 0 {
		return fmt.Errorf("bootstrap release is incomplete")
	}
	outDir = filepath.Clean(outDir)
	artifacts := filepath.Join(outDir, "artifacts")
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		return fmt.Errorf("create bootstrap release directory: %w", err)
	}
	manifest := Manifest{Version: version}
	for _, file := range files {
		body, err := readReleaseFile(file.Path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		dest := filepath.Join(artifacts, digest)
		if err = writeRegular(dest, body, 0o644); err != nil {
			return err
		}
		manifest.Artifacts = append(manifest.Artifacts, Artifact{
			Name: file.Name, OS: file.OS, Arch: file.Arch, SHA256: digest, Size: int64(len(body)),
		})
	}
	signed, err := Sign(key, manifest)
	if err != nil {
		return err
	}
	public, err := PublicPEM(key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	if err = writeRegular(filepath.Join(outDir, "manifest.json"), signed, 0o600); err != nil {
		return err
	}
	return writeRegular(filepath.Join(outDir, "public.pem"), []byte(public), 0o644)
}

func readReleaseFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > MaxArtifact {
		return nil, fmt.Errorf("bootstrap release file is rejected")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap release file is rejected")
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, MaxArtifact+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, fmt.Errorf("bootstrap release file is rejected")
	}
	return body, nil
}

func writeRegular(path string, body []byte, mode os.FileMode) error {
	if strings.Contains(filepath.Base(path), "..") {
		return fmt.Errorf("bootstrap release path is rejected")
	}
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, body, mode); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write bootstrap release: %w", err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// MaxArtifact is the largest file a signed release may contain.
const MaxArtifact = 64 << 20
