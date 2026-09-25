// Package writeflags matches a write path to an operator flag.
//
// Threats: a relative path, a traversal component, the filesystem root, or
// two flags on the same path are rejected at load. Restrict denies every
// uid that is not listed. Monitor never turns a denied write into an allow.
package writeflags

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	ModeMonitor  = "monitor"
	ModeRestrict = "restrict"
)

// Effect is what a matching flag does to one write.
type Effect int

const (
	EffectNone Effect = iota
	EffectMonitor
	EffectDeny
)

// Spec is one configured flag.
type Spec struct {
	Path      string
	Mode      string
	AllowUIDs []uint32
}

// Decision is the most specific flag that covers a path.
type Decision struct {
	Effect   Effect
	FlagPath string
	Mode     string
}

type flag struct {
	path  string
	mode  string
	allow map[uint32]struct{}
}

// Set is an immutable collection of flags.
type Set struct {
	flags []flag
}

// Load checks every flag and returns a set. An empty spec list is a set
// that matches nothing.
func Load(specs []Spec) (*Set, error) {
	if len(specs) > 64 {
		return nil, fmt.Errorf("write flags exceed limit")
	}
	seen := map[string]struct{}{}
	flags := make([]flag, 0, len(specs))
	for _, spec := range specs {
		path, err := cleanPath(spec.Path)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[path]; ok {
			return nil, fmt.Errorf("write flag %s is duplicated", path)
		}
		seen[path] = struct{}{}
		switch spec.Mode {
		case ModeMonitor:
			if len(spec.AllowUIDs) != 0 {
				return nil, fmt.Errorf("write flag %s monitor does not take allow uids", path)
			}
			flags = append(flags, flag{path: path, mode: ModeMonitor})
		case ModeRestrict:
			if len(spec.AllowUIDs) > 32 {
				return nil, fmt.Errorf("write flag %s allow list exceeds limit", path)
			}
			allow := make(map[uint32]struct{}, len(spec.AllowUIDs))
			for _, uid := range spec.AllowUIDs {
				allow[uid] = struct{}{}
			}
			flags = append(flags, flag{path: path, mode: ModeRestrict, allow: allow})
		default:
			return nil, fmt.Errorf("write flag %s mode is invalid", path)
		}
	}
	return &Set{flags: flags}, nil
}

func cleanPath(path string) (string, error) {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) {
		return "", fmt.Errorf("write flag path must be absolute")
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("write flag path must not contain ..")
		}
	}
	clean := filepath.Clean(path)
	if clean == "/" || clean == "." {
		return "", fmt.Errorf("write flag path is too broad")
	}
	return clean, nil
}

// Apply reports the strongest match across the lexical path and any resolved
// path. Restrict wins over monitor. A longer flag path wins within one effect.
func (s *Set) Apply(paths []string, uid uint32) Decision {
	if s == nil {
		return Decision{}
	}
	best := Decision{}
	for _, raw := range paths {
		if raw == "" || !filepath.IsAbs(raw) {
			continue
		}
		path := filepath.Clean(raw)
		for _, flag := range s.flags {
			if path != flag.path && !strings.HasPrefix(path, flag.path+string(filepath.Separator)) {
				continue
			}
			decision := Decision{FlagPath: flag.path, Mode: flag.mode, Effect: EffectMonitor}
			if flag.mode == ModeRestrict {
				if _, ok := flag.allow[uid]; ok {
					continue
				}
				decision.Effect = EffectDeny
			}
			if better(decision, best) {
				best = decision
			}
		}
	}
	return best
}

func better(next, best Decision) bool {
	if best.Effect == EffectNone {
		return true
	}
	if next.Effect == EffectDeny && best.Effect != EffectDeny {
		return true
	}
	if next.Effect != best.Effect {
		return false
	}
	return len(next.FlagPath) > len(best.FlagPath)
}
