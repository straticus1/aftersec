// Package stolen records which enrolled endpoints an operator has marked stolen.
//
// Threats: a path that escapes the registry is rejected. Clearing a mark
// stops new photos. Photos already stored stay available to that tenant.
package stolen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Registry struct {
	root string
}

func Open(dir string) (*Registry, error) {
	clean := filepath.Clean(dir)
	if dir == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("stolen registry directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create stolen registry: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("protect stolen registry: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Registry{root: abs}, nil
}

func (r *Registry) Mark(tenant, endpoint string) error {
	path, err := r.file(tenant, endpoint, false)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(path, []byte("stolen\n"), 0600); err != nil {
		return fmt.Errorf("record stolen mark: %w", err)
	}
	_ = os.Remove(path + ".cleared")
	return nil
}

func (r *Registry) Clear(tenant, endpoint string) error {
	path, err := r.file(tenant, endpoint, false)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err = os.WriteFile(path+".cleared", []byte("cleared\n"), 0600); err != nil {
		return fmt.Errorf("record stolen clear: %w", err)
	}
	return nil
}

// State reports an active stolen mark, or a clear that still needs delivery.
func (r *Registry) State(tenant, endpoint string) (marked bool, clearPending bool) {
	path, err := r.file(tenant, endpoint, false)
	if err != nil {
		return false, false
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
		return true, false
	}
	if info, statErr := os.Lstat(path + ".cleared"); statErr == nil && info.Mode().IsRegular() {
		return false, true
	}
	return false, false
}

func (r *Registry) file(tenant, endpoint string, cleared bool) (string, error) {
	if r == nil || !safe(tenant) || !safe(endpoint) {
		return "", fmt.Errorf("stolen identity is invalid")
	}
	name := endpoint
	if cleared {
		name += ".cleared"
	}
	path := filepath.Join(r.root, tenant, name)
	rel, err := filepath.Rel(r.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("stolen identity is invalid")
	}
	return path, nil
}

func safe(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 128 || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == ':' || r == '-':
		default:
			return false
		}
	}
	return true
}
