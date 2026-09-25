// Package provenance is the cross-OS execution provenance service.
//
// Threats: a missing parent, a symlink, a path outside the trusted prefixes,
// or Windows (which has no exec sensor here) is not an allow. A trusted
// prefix is boundary-aware, so /usr/bin does not cover /usr/bin-evil or
// /usr/local.
package provenance

import "strings"

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
	Class    Class  `json:"class"`
}

var trusted = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/System/"}

// Observe classifies one exec. regular is false for a symlink or anything
// that is not a regular file. Windows is unsupported rather than allowed.
func Observe(platform, path, parent string, regular bool) Observation {
	obs := Observation{Platform: normalize(platform), Path: path, Parent: parent, Class: Suspicious}
	if obs.Platform == "windows" || obs.Platform == "" {
		obs.Class = Unsupported
		return obs
	}
	if obs.Platform != "darwin" && obs.Platform != "linux" {
		obs.Class = Unsupported
		return obs
	}
	if !regular || parent == "" || strings.Contains(path, "\x00") || strings.Contains(parent, "\x00") {
		return obs
	}
	if !trustedPath(path) {
		return obs
	}
	obs.Class = Allow
	return obs
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
