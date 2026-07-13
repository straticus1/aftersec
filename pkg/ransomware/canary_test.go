package ransomware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanaryManagerPlantsPrivateDecoysAndRecognizesCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	m := NewCanaryManager([]string{dir})
	paths, err := m.Plant()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths=%v", paths)
	}
	info, err := os.Stat(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if !m.IsCanary(filepath.Join(dir, ".", filepath.Base(paths[0]))) {
		t.Fatal("canonical canary path not recognized")
	}
}

func TestCanaryManagerRejectsSymlinkDirectory(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCanaryManager([]string{link}).Plant(); err == nil {
		t.Fatal("expected symlink directory rejection")
	}
}
