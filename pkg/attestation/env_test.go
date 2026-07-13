package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func envGetter(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func writeTrustKey(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attestation-root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildRuntimeFromEnvironmentDevelopmentRequiresBothPlatformRoots(t *testing.T) {
	_, _, err := BuildRuntimeFromEnvironment(envGetter(map[string]string{
		"ENROLLMENT_MODE":         "development",
		"ATTESTATION_DARWIN_ROOT": writeTrustKey(t),
	}), nil)
	if err == nil {
		t.Fatal("development startup accepted missing Linux attestation root")
	}
}

func TestBuildRuntimeFromEnvironmentDevelopmentIsExplicitAndBounded(t *testing.T) {
	runtime, ttl, err := BuildRuntimeFromEnvironment(envGetter(map[string]string{
		"ENROLLMENT_MODE":          "development",
		"ENROLLMENT_CERT_LIFETIME": "15m",
		"ATTESTATION_DARWIN_ROOT":  writeTrustKey(t),
		"ATTESTATION_LINUX_ROOT":   writeTrustKey(t),
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Service == nil || len(runtime.DevelopmentCAPEM) == 0 || ttl.String() != "15m0s" {
		t.Fatalf("unexpected development runtime or TTL: %#v %s", runtime, ttl)
	}
}

func TestBuildRuntimeFromEnvironmentRejectsExcessiveCertificateLifetime(t *testing.T) {
	_, _, err := BuildRuntimeFromEnvironment(envGetter(map[string]string{
		"ENROLLMENT_MODE":          "development",
		"ENROLLMENT_CERT_LIFETIME": "168h",
		"ATTESTATION_DARWIN_ROOT":  writeTrustKey(t),
		"ATTESTATION_LINUX_ROOT":   writeTrustKey(t),
	}), nil)
	if err == nil {
		t.Fatal("startup accepted an enrollment certificate lifetime over 24 hours")
	}
}
