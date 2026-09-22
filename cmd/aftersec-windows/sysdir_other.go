//go:build !windows

package main

import (
	"fmt"
	"path/filepath"
)

func systemWindowsRoot() (string, error) {
	return "", fmt.Errorf("SystemRoot must be an absolute path")
}

func machineModulePath(root string) string {
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "Modules")
}
