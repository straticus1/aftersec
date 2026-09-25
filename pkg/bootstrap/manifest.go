// Package bootstrap signs and checks the release a new endpoint is allowed to install.
//
// Threats: a bad signature, a re-encoded payload, an unknown artifact name,
// a non-canonical hash, or an oversized body is rejected. The manifest does
// not carry a command line or a download URL.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

const MaxManifest = 64 * 1024

var allowedNames = map[string]struct{}{
	"aftersec": {}, "aftersecd": {}, "aftersec-display": {}, "management-ca": {},
}

// Artifact is one file the bootstrap may install.
type Artifact struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the signed set of artifacts.
type Manifest struct {
	Version   string     `json:"version"`
	Artifacts []Artifact `json:"artifacts"`
}

type envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Sign returns the exact bytes the endpoint must verify.
func Sign(key ed25519.PrivateKey, manifest Manifest) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bootstrap signing key is invalid")
	}
	payload, err := canonical(manifest)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)),
	})
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap manifest: %w", err)
	}
	return body, nil
}

// Verify checks the signature and the artifact list.
func Verify(public ed25519.PublicKey, raw []byte) (Manifest, error) {
	if len(public) != ed25519.PublicKeySize || len(raw) == 0 || len(raw) > MaxManifest {
		return Manifest{}, fmt.Errorf("bootstrap manifest rejected")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env envelope
	if err := dec.Decode(&env); err != nil || dec.More() {
		return Manifest{}, fmt.Errorf("bootstrap manifest rejected")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxManifest {
		return Manifest{}, fmt.Errorf("bootstrap manifest rejected")
	}
	signature, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, payload, signature) {
		return Manifest{}, fmt.Errorf("bootstrap manifest rejected")
	}
	dec = json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var manifest Manifest
	if err = dec.Decode(&manifest); err != nil || dec.More() {
		return Manifest{}, fmt.Errorf("bootstrap manifest rejected")
	}
	if err = validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func canonical(manifest Manifest) ([]byte, error) {
	if err := validate(manifest); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap manifest: %w", err)
	}
	if len(payload) > MaxManifest {
		return nil, fmt.Errorf("bootstrap manifest exceeds limit")
	}
	return payload, nil
}

func validate(manifest Manifest) error {
	if manifest.Version == "" || len(manifest.Version) > 32 || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 8 {
		return fmt.Errorf("bootstrap manifest rejected")
	}
	seen := map[string]struct{}{}
	for _, artifact := range manifest.Artifacts {
		if _, ok := allowedNames[artifact.Name]; !ok {
			return fmt.Errorf("bootstrap artifact name rejected")
		}
		if artifact.OS != "darwin" && artifact.OS != "linux" {
			return fmt.Errorf("bootstrap artifact platform rejected")
		}
		if artifact.Arch != "amd64" && artifact.Arch != "arm64" {
			return fmt.Errorf("bootstrap artifact platform rejected")
		}
		if len(artifact.SHA256) != sha256.Size*2 || artifact.Size < 1 || artifact.Size > 64<<20 || !lowerHex(artifact.SHA256) {
			return fmt.Errorf("bootstrap artifact rejected")
		}
		key := artifact.Name + "\x00" + artifact.OS + "\x00" + artifact.Arch
		if _, ok := seen[key]; ok {
			return fmt.Errorf("bootstrap artifact is duplicated")
		}
		seen[key] = struct{}{}
	}
	return nil
}

// PublicPEM encodes a release public key for the bootstrap script.
func PublicPEM(public ed25519.PublicKey) (string, error) {
	if len(public) != ed25519.PublicKeySize {
		return "", fmt.Errorf("bootstrap public key is invalid")
	}
	der, err := pemPublic(public)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func lowerHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
