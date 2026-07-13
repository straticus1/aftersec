package threatintel

// Threats: IOC values and types must not inject additional URL path segments.
// This does not validate whether an IOC is semantically valid for its type.

import (
	"strings"
	"testing"
)

func TestIOCPath_EscapesUntrustedSegments(t *testing.T) {
	path := iocPath("hash/../../admin", "bad/value?redirect=attacker")

	if strings.Contains(path, "../") || strings.Contains(path, "?redirect=") {
		t.Fatalf("unescaped IOC path: %q", path)
	}
	want := "/ioc/hash%2F..%2F..%2Fadmin/bad%2Fvalue%3Fredirect=attacker"
	if path != want {
		t.Fatalf("IOC path = %q, want %q", path, want)
	}
}
