package attestation

import (
	"database/sql"
	"fmt"
	"time"
)

// BuildRuntimeFromEnvironment loads enrollment trust configuration without
// defaults that weaken production. Threats: missing platform roots, invalid
// modes, malformed durations, and overly long credentials prevent startup.
func BuildRuntimeFromEnvironment(getenv func(string) string, db *sql.DB) (*Runtime, time.Duration, error) {
	if getenv == nil {
		return nil, 0, fmt.Errorf("environment reader is required")
	}
	lifetime := 15 * time.Minute
	if raw := getenv("ENROLLMENT_CERT_LIFETIME"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, 0, fmt.Errorf("parse ENROLLMENT_CERT_LIFETIME: %w", err)
		}
		lifetime = parsed
	}
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return nil, 0, fmt.Errorf("enrollment certificate lifetime must be positive and at most 24 hours")
	}
	darwinRoot := getenv("ATTESTATION_DARWIN_ROOT")
	linuxRoot := getenv("ATTESTATION_LINUX_ROOT")
	if darwinRoot == "" || linuxRoot == "" {
		return nil, 0, fmt.Errorf("Darwin and Linux attestation trust roots are required")
	}
	verifier, err := LoadSignedQuoteVerifier(map[string]string{
		"darwin": darwinRoot,
		"linux":  linuxRoot,
	})
	if err != nil {
		return nil, 0, err
	}
	runtime, err := BuildRuntime(RuntimeConfig{
		Mode:                getenv("ENROLLMENT_MODE"),
		CACertificateFile:   getenv("ENROLLMENT_CA_CERT"),
		CAPrivateKeyFile:    getenv("ENROLLMENT_CA_KEY"),
		CertificateLifetime: lifetime,
		CodeLifetime:        10 * time.Minute,
	}, db, verifier)
	if err != nil {
		return nil, 0, err
	}
	return runtime, lifetime, nil
}
