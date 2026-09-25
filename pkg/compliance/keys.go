package compliance

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPrivateKey reads an unencrypted PKCS#8 Ed25519 key. The file must be a
// regular file and must not be group- or world-accessible.
//
// Threats: a symlink, oversized file, or world-readable signing key is rejected.
// The key bytes are not logged.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := readKeyFile(path, true)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode compliance evidence key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse compliance evidence key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("compliance evidence key is not Ed25519")
	}
	return key, nil
}

// LoadPublicKey reads a PKIX Ed25519 public key from a regular file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readKeyFile(path, false)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode compliance public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse compliance public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("compliance public key is not Ed25519")
	}
	return key, nil
}

func readKeyFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read compliance key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("compliance key must be a regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("compliance evidence key is too accessible")
	}
	if info.Size() == 0 || info.Size() > 16<<10 {
		return nil, fmt.Errorf("compliance key has an invalid size")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compliance key: %w", err)
	}
	return data, nil
}
