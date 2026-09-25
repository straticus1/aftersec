// Package preserve records which endpoints an operator marked for evidence collection.
//
// Threats: a path that escapes the registry is rejected. The file stores only
// the reason and incident id. Clearing the mark stops a new collection.
package preserve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	evidence "aftersec/pkg/preserve"
)

type Registry struct {
	root string
}

func Open(dir string) (*Registry, error) {
	clean := filepath.Clean(dir)
	if dir == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("preserve registry directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create preserve registry: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("protect preserve registry: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Registry{root: abs}, nil
}

func (r *Registry) Mark(tenant, endpoint, reason, incident string) error {
	if !evidence.ValidReason(reason) || !evidence.ValidIncident(incident) {
		return fmt.Errorf("preserve mark is invalid")
	}
	path, err := r.file(tenant, endpoint)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body := reason + "\n" + incident + "\n"
	if err = os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("record preserve mark: %w", err)
	}
	return nil
}

func (r *Registry) Clear(tenant, endpoint string) error {
	path, err := r.file(tenant, endpoint)
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear preserve mark: %w", err)
	}
	return nil
}

// State returns the mark only when both fields still validate.
func (r *Registry) State(tenant, endpoint string) (reason, incident string, ok bool) {
	path, err := r.file(tenant, endpoint)
	if err != nil {
		return "", "", false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 256 {
		return "", "", false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) != 3 || lines[2] != "" || !evidence.ValidReason(lines[0]) || !evidence.ValidIncident(lines[1]) {
		return "", "", false
	}
	return lines[0], lines[1], true
}

func (r *Registry) file(tenant, endpoint string) (string, error) {
	if r == nil || !safe(tenant) || !safe(endpoint) {
		return "", fmt.Errorf("preserve identity is invalid")
	}
	path := filepath.Join(r.root, tenant, endpoint)
	rel, err := filepath.Rel(r.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("preserve identity is invalid")
	}
	return path, nil
}

func safe(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 128 || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		if r == '/' || r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
