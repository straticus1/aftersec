//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func systemWindowsRoot() (string, error) {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", err
	}
	return validateAndCleanRoot(dir)
}

func machineModulePath(root string) string {
	pshome := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "Modules")
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || pf == "" || isUNC(pf) || !filepath.IsAbs(pf) {
		return pshome
	}
	allUsers := filepath.Join(filepath.Clean(pf), "WindowsPowerShell", "Modules")
	return pshome + string(os.PathListSeparator) + allUsers
}
