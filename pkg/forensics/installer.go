package forensics

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// PkgAnalysisResult holds the extracted scripts from a macOS Installer Package
type PkgAnalysisResult struct {
	PreinstallScript    string
	PostinstallScript   string
	RawScriptsExtracted int
	Error               error
}

// AnalyzeInstaller uses native pkgutil to recursively dump an installer package 
// into a temporary sandbox and extract potentially dangerous root-level execution scripts.
func AnalyzeInstaller(ctx context.Context, pkgPath string) (*PkgAnalysisResult, error) {
	res := &PkgAnalysisResult{}

	// Create a temporary extraction sandbox
	tmpDir, err := os.MkdirTemp("", "aftersec-pkg-extract-*")
	if err != nil {
		res.Error = fmt.Errorf("failed to create sandbox: %v", err)
		return res, res.Error
	}
	defer os.RemoveAll(tmpDir)

	// Apple's pkgutil securely expands the XAR structure
	cmd := exec.CommandContext(ctx, "pkgutil", "--expand-full", pkgPath, filepath.Join(tmpDir, "expanded"))
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Error = fmt.Errorf("pkgutil expansion timed out (exceeded deadline). Package is too massive for safe analysis")
			return res, res.Error
		}
		res.Error = fmt.Errorf("pkgutil expansion failed (is this a valid .pkg file?): %v", err)
		return res, res.Error
	}

	// Walk the expanded directory looking for 'Scripts' folders
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() {
			fileName := info.Name()
			if fileName == "preinstall" || fileName == "postinstall" {
				b, readErr := os.ReadFile(path)
				if readErr == nil {
					if fileName == "preinstall" {
						res.PreinstallScript = string(b)
					} else if fileName == "postinstall" {
						res.PostinstallScript = string(b)
					}
					res.RawScriptsExtracted++
				}
			}
		}
		return nil
	})

	if err != nil {
		res.Error = fmt.Errorf("failed to walk extracted payload: %v", err)
		return res, res.Error
	}

	return res, nil
}
