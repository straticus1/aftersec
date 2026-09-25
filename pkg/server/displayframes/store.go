// Package displayframes stores one JPEG per signed display command.
//
// Threats: a path that escapes the store, a symlink, or an identity with a
// slash is rejected. The image bytes are not written to the audit log.
package displayframes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type Store struct {
	root string
}

func Open(dir string) (*Store, error) {
	clean := filepath.Clean(dir)
	if dir == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("display frame directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create display frame directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("protect display frame directory: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

func (s *Store) Save(tenant, endpoint, commandID string, frame []byte) error {
	path, err := s.path(tenant, endpoint, commandID)
	if err != nil {
		return err
	}
	if len(frame) == 0 {
		return fmt.Errorf("display frame is empty")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create display frame directory: %w", err)
	}
	tmp := path + ".partial"
	if err = os.WriteFile(tmp, frame, 0600); err != nil {
		return fmt.Errorf("write display frame: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store display frame: %w", err)
	}
	return nil
}

func (s *Store) Open(tenant, endpoint, commandID string) (*os.File, error) {
	path, err := s.path(tenant, endpoint, commandID)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		return nil, fmt.Errorf("display frame is not available")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("display frame is not available")
	}
	return f, nil
}

func (s *Store) path(tenant, endpoint, commandID string) (string, error) {
	if s == nil || s.root == "" || !safeID(tenant) || !safeID(endpoint) || !commandIDOK(commandID) {
		return "", fmt.Errorf("display frame identity is invalid")
	}
	path := filepath.Join(s.root, tenant, endpoint, commandID+".jpg")
	rel, err := filepath.Rel(s.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("display frame path escaped")
	}
	return path, nil
}

func safeID(id string) bool {
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

func commandIDOK(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
