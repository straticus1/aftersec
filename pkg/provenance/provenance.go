// Package provenance is the cross-OS execution provenance service.
//
// Threats: a missing parent, a symlink, a path outside the trusted prefixes,
// or Windows (which has no exec sensor here) is not an allow. A trusted
// prefix is boundary-aware, so /usr/bin does not cover /usr/bin-evil or
// /usr/local.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

type Class string

const (
	Allow       Class = "allow"
	Suspicious  Class = "suspicious"
	Unsupported Class = "unsupported"
)

type Observation struct {
	Platform string `json:"platform"`
	Path     string `json:"path"`
	Parent   string `json:"parent,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Class    Class  `json:"class"`
}

const maxHashBytes = 32 << 20

var trusted = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/System/"}

// Inspect hashes a regular, non-symlink file that is not group- or world-writable.
// A symlink or unreadable file returns sealed false. The hash is empty when the
// file is larger than 32MiB.
func Inspect(path string) (hash string, sealed bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false
	}
	if info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maxHashBytes {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(f, maxHashBytes+1))
	if err != nil || n != info.Size() {
		return "", false
	}
	return hex.EncodeToString(sum.Sum(nil)), true
}

// Observe classifies one exec. Allow requires a sealed content hash.
// Windows is unsupported rather than allowed.
func Observe(platform, path, parent, hash string, sealed bool) Observation {
	obs := Observation{Platform: normalize(platform), Path: path, Parent: parent, SHA256: hash, Class: Suspicious}
	if obs.Platform == "windows" || obs.Platform == "" || (obs.Platform != "darwin" && obs.Platform != "linux") {
		obs.Class = Unsupported
		return obs
	}
	if !sealed || parent == "" || !validHash(hash) || strings.Contains(path, "\x00") || strings.Contains(parent, "\x00") || !trustedPath(path) {
		return obs
	}
	obs.Class = Allow
	return obs
}

func validHash(hash string) bool {
	if len(hash) != sha256.Size*2 {
		return false
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func trustedPath(path string) bool {
	if path == "" || strings.Contains(path, "..") {
		return false
	}
	for _, prefix := range trusted {
		if strings.HasPrefix(path, prefix) && !strings.Contains(path[len(prefix):], "..") {
			return true
		}
	}
	return false
}

func normalize(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "darwin", "macos":
		return "darwin"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return ""
	}
}
