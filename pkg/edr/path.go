package edr

import (
	"path/filepath"
	"strings"
)

// JoinRenameDest combines an Endpoint Security rename destination. An existing
// destination path wins. A new path is accepted only as a single file name
// inside an absolute directory.
func JoinRenameDest(existing, dir, name string) string {
	if existing != "" {
		return existing
	}
	if !filepath.IsAbs(dir) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return ""
	}
	return filepath.Join(dir, name)
}
