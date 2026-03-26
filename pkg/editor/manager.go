package editor

import (
	"errors"
	"os"
	"path/filepath"

	"aftersec/defaults"
)

// Manager handles localized caching, saving, and rolling back of custom security rules and scripts.
type Manager struct {
	BaseDir string
}

// NewManager initializes the rule directories on disk inside the user's home folder.
func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	base := filepath.Join(home, ".aftersec")
	
	for _, sub := range []string{"rules", "scripts"} {
		if err := os.MkdirAll(filepath.Join(base, sub), 0755); err != nil {
			return nil, err
		}
	}
	m := &Manager{BaseDir: base}
	_ = m.SeedDemos()
	return m, nil
}

// ListFiles enumerates available files within a specific sub-domain (e.g. "rules" or "scripts")
func (m *Manager) ListFiles(subDir string) ([]string, error) {
	if subDir == "dist-scripts" {
		entries, err := defaults.StarlarkScripts.ReadDir("starlark")
		if err != nil {
			return nil, err
		}
		var files []string
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, e.Name())
			}
		}
		return files, nil
	}
	dir := filepath.Join(m.BaseDir, subDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	return files, nil
}

// ReadFile loads the precise contents of a script block.
func (m *Manager) ReadFile(subDir, name string) (string, error) {
	if subDir == "dist-scripts" {
		b, err := defaults.StarlarkScripts.ReadFile("starlark/" + name)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	path := filepath.Join(m.BaseDir, subDir, name)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// WriteFile securely streams edits directly into the localized registry.
func (m *Manager) WriteFile(subDir, name, content string) error {
	if subDir == "dist-scripts" {
		return errors.New("cannot write to read-only distribution scripts")
	}
	path := filepath.Join(m.BaseDir, subDir, name)
	return os.WriteFile(path, []byte(content), 0644)
}

// DeleteFile removes a script or rule from the active state engine permanently.
func (m *Manager) DeleteFile(subDir, name string) error {
	if subDir == "dist-scripts" {
		return errors.New("cannot delete read-only distribution scripts")
	}
	path := filepath.Join(m.BaseDir, subDir, name)
	return os.Remove(path)
}

// SeedDemos populates the scripts folder with initial distribution scripts if empty.
func (m *Manager) SeedDemos() error {
	scriptsDir := filepath.Join(m.BaseDir, "scripts")
	entries, _ := os.ReadDir(scriptsDir)
	if len(entries) == 0 {
		distEntries, err := defaults.StarlarkScripts.ReadDir("starlark")
		if err == nil {
			for _, e := range distEntries {
				if !e.IsDir() {
					content, err := defaults.StarlarkScripts.ReadFile("starlark/" + e.Name())
					if err == nil {
						os.WriteFile(filepath.Join(scriptsDir, e.Name()), content, 0644)
					}
				}
			}
		}
	}
	return nil
}
