package binaryauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectRejectsNonRegularAndOversizedFiles(t *testing.T) {
	if _, err := InspectExecutable(t.TempDir()); err == nil || strings.Contains(err.Error(), "%!w") {
		t.Fatalf("directory: %v", err)
	}
	path := filepath.Join(t.TempDir(), "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(maxExecutableBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectExecutable(path); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized: %v", err)
	}
}
