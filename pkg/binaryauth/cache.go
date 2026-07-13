package binaryauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type cacheEnvelope struct {
	Policy   SignedPolicy `json:"policy"`
	Checksum string       `json:"checksum"`
}

// SavePolicy atomically stores a checksummed signed policy with private permissions.
// Threats: partial writes and offline cache tampering are rejected; filesystem rollback is also rejected by Authorizer version state.
func SavePolicy(path string, p SignedPolicy) error {
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	sum := sha256.Sum256(body)
	wire, err := json.Marshal(cacheEnvelope{Policy: p, Checksum: hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, wire, 0600); err != nil {
		return fmt.Errorf("write policy cache: %w", err)
	}
	if err = os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install policy cache: %w", err)
	}
	return nil
}
func LoadPolicy(path string) (SignedPolicy, error) {
	wire, err := os.ReadFile(path)
	if err != nil {
		return SignedPolicy{}, fmt.Errorf("read policy cache: %w", err)
	}
	if len(wire) > 16<<20 {
		return SignedPolicy{}, fmt.Errorf("policy cache exceeds limit")
	}
	var env cacheEnvelope
	if json.Unmarshal(wire, &env) != nil {
		return SignedPolicy{}, fmt.Errorf("decode policy cache")
	}
	body, err := json.Marshal(env.Policy)
	if err != nil {
		return SignedPolicy{}, err
	}
	want, err := hex.DecodeString(env.Checksum)
	if err != nil {
		return SignedPolicy{}, fmt.Errorf("decode policy checksum")
	}
	got := sha256.Sum256(body)
	if len(want) != sha256.Size || subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return SignedPolicy{}, fmt.Errorf("policy cache checksum mismatch")
	}
	return env.Policy, nil
}
