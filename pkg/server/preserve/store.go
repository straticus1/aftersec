package preserve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	evidence "aftersec/pkg/preserve"
)

// Store keeps one gzip archive per incident.
//
// Threats: a path that escapes the store or a symlink is rejected. The
// archive is not written to the event journal.
type Store struct {
	root string
}

func OpenStore(dir string) (*Store, error) {
	clean := filepath.Clean(dir)
	if dir == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("preserve store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create preserve store: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("protect preserve store: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

func (s *Store) Save(tenant, endpoint, incident string, bundle []byte) error {
	if len(bundle) == 0 || len(bundle) > 256*1024 || !evidence.ValidIncident(incident) {
		return fmt.Errorf("preserve bundle is invalid")
	}
	path, err := s.path(tenant, endpoint, incident)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create preserve directory: %w", err)
	}
	tmp := path + ".partial"
	if err = os.WriteFile(tmp, bundle, 0o600); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write preserve bundle: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store preserve bundle: %w", err)
	}
	return nil
}

func (s *Store) Open(tenant, endpoint, incident string) (*os.File, error) {
	path, err := s.path(tenant, endpoint, incident)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		return nil, fmt.Errorf("preserve bundle is not available")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("preserve bundle is not available")
	}
	return f, nil
}

func (s *Store) path(tenant, endpoint, incident string) (string, error) {
	if s == nil || !safe(tenant) || !safe(endpoint) || !evidence.ValidIncident(incident) {
		return "", fmt.Errorf("preserve identity is invalid")
	}
	path := filepath.Join(s.root, tenant, endpoint, incident+".gz")
	rel, err := filepath.Rel(s.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("preserve identity is invalid")
	}
	return path, nil
}
