package ransomware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type CanaryManager struct {
	directories []string
	mu          sync.RWMutex
	paths       map[string]struct{}
}

func NewCanaryManager(d []string) *CanaryManager {
	return &CanaryManager{directories: append([]string(nil), d...), paths: map[string]struct{}{}}
}

// Plant creates unpredictable private decoy files without following directory symlinks.
// Threats: ransomware canary access is observable; malware that identifies/avoids decoys remains out of scope.
func (m *CanaryManager) Plant() ([]string, error) {
	if len(m.directories) == 0 || len(m.directories) > 1024 {
		return nil, fmt.Errorf("bounded canary directories are required")
	}
	created := []string{}
	for _, dir := range m.directories {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsafe canary directory %q", dir)
		}
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		var id [8]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, fmt.Errorf("generate canary name: %w", err)
		}
		path := filepath.Join(absolute, ".aftersec-decoy-"+hex.EncodeToString(id[:])+".docx")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, fmt.Errorf("create canary: %w", err)
		}
		if _, err = f.WriteString("AfterSec protected document\n"); err != nil {
			f.Close()
			return nil, fmt.Errorf("write canary: %w", err)
		}
		if err = f.Close(); err != nil {
			return nil, fmt.Errorf("close canary: %w", err)
		}
		m.mu.Lock()
		m.paths[filepath.Clean(path)] = struct{}{}
		m.mu.Unlock()
		created = append(created, path)
	}
	return created, nil
}
func (m *CanaryManager) IsCanary(path string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.paths[filepath.Clean(absolute)]
	return ok
}
