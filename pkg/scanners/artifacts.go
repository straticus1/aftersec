package scanners

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"aftersec/pkg/bintrace"
	"aftersec/pkg/codescan"
	"aftersec/pkg/core"
)

const (
	maxVisited = 500
	maxDepth   = 4
	maxHits    = 40
)

// ScanArtifacts walks persistence directories for executables and source files.
// An unreadable directory is a failed finding. A parsed binary with no import
// indicator is reported as no-indicator, which is not a verdict of benign.
func ScanArtifacts(addFinding func(core.Finding)) {
	scanRoots(artifactRoots(), addFinding)
}

func scanRoots(roots []string, addFinding func(core.Finding)) {
	hits := 0
	visited := 0
	for _, root := range roots {
		if hits >= maxHits {
			break
		}
		info, err := os.Lstat(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			addFinding(artifactFailed(root, err.Error()))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			addFinding(artifactFailed(root, "persistence path is not a real directory"))
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if hits >= maxHits || visited >= maxVisited {
				return fs.SkipAll
			}
			if walkErr != nil {
				addFinding(artifactFailed(path, walkErr.Error()))
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if skipDir(d.Name()) || depth(root, path) > maxDepth {
					return fs.SkipDir
				}
				return nil
			}
			visited++
			ext := strings.ToLower(filepath.Ext(path))
			if sourceExt(ext) {
				for _, f := range codescan.ScanFile(path) {
					if f.Refused {
						addFinding(artifactFailed(path, f.Detail))
					} else {
						addFinding(core.Finding{
							Category:    "Source Scan",
							Name:        f.Rule,
							Description: "Single-line source pattern. This is not a full SAST pass.",
							Severity:    core.High,
							CurrentVal:  fmt.Sprintf("%s:%d", filepath.Base(path), f.Line),
							ExpectedVal: "no matched pattern",
							LogContext:  f.Detail,
							Passed:      false,
						})
					}
					hits++
					if hits >= maxHits {
						return fs.SkipAll
					}
				}
				return nil
			}
			if !looksExecutable(path, d) {
				return nil
			}
			report := bintrace.Inspect(path)
			switch report.Verdict {
			case "refused":
				if report.Reason == "not a mach-o, elf, or pe file" {
					return nil
				}
				addFinding(artifactFailed(path, report.Reason))
				hits++
			case "suspicious":
				addFinding(core.Finding{
					Category:    "Binary Trace",
					Name:        "Suspicious import chain",
					Description: "Static libraries and imports match an injection or credential-access chain. The file was not executed, and this is not proof of malice.",
					Severity:    core.High,
					CurrentVal:  report.Format + " " + filepath.Base(path),
					ExpectedVal: "no injection or credential-import chain",
					LogContext:  report.Reason,
					Passed:      false,
				})
				hits++
			case "no-indicator":
				addFinding(core.Finding{
					Category:    "Binary Trace",
					Name:        "Import trace",
					Description: "Parsed linked libraries and imports. No indicator is not a benign verdict.",
					Severity:    core.LogOnly,
					CurrentVal:  fmt.Sprintf("%s libs=%d imports=%d", report.Format, len(report.Libraries), len(report.Symbols)),
					ExpectedVal: "reviewed",
					LogContext:  filepath.Base(path),
					Passed:      true,
				})
				hits++
			}
			return nil
		})
		if err != nil && err != fs.SkipAll {
			addFinding(artifactFailed(root, err.Error()))
		}
	}
}

func artifactRoots() []string {
	home, err := os.UserHomeDir()
	roots := []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"}
	if runtime.GOOS == "linux" {
		roots = []string{"/etc/systemd/system", "/usr/local/bin"}
	}
	if err == nil && home != "" {
		if runtime.GOOS == "linux" {
			roots = append(roots, filepath.Join(home, ".config", "systemd", "user"))
		} else {
			roots = append(roots, filepath.Join(home, "Library", "LaunchAgents"))
		}
	}
	return roots
}

func artifactFailed(path, why string) core.Finding {
	return core.Finding{
		Category:    "Binary Trace",
		Name:        "Artifact scan",
		Description: "The file or directory could not be scanned. That is not a pass.",
		Severity:    core.High,
		CurrentVal:  filepath.Base(path),
		ExpectedVal: "readable regular file",
		LogContext:  why,
		Passed:      false,
	}
}

func sourceExt(ext string) bool {
	switch ext {
	case ".go", ".py", ".js", ".java", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".sh", ".bash":
		return true
	default:
		return false
	}
}

func looksExecutable(path string, d fs.DirEntry) bool {
	info, err := d.Info()
	if err != nil {
		return false
	}
	if info.Mode()&0o111 != 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".dylib" || ext == ".so" || ext == ".exe" || ext == ".dll"
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "Library":
		return true
	default:
		return false
	}
}

func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(rel, string(os.PathSeparator))
}
