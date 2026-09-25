// Package codescan is a bounded source check for files the endpoint scan
// actually opens. It is not Semgrep and it is not gosec.
//
// Threats: a file can be a symlink, oversized, or contain a secret on the
// matched line. Symlinks and oversized files are refused. Matched lines are
// clipped and secret-shaped tokens are withheld. A file with no match is not
// proven safe. Patterns are single-line and do not track taint across functions.
package codescan

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxSourceBytes int64 = 1 << 20

var (
	errSymlink   = errors.New("symlink refused")
	errOversize  = errors.New("source exceeds 1 MiB")
	errNotSource = errors.New("unsupported source type")
	secretVal    = regexp.MustCompile(`(?i)(sk-|sk-ant-|ghp_|github_pat_|xox[baprs]-|AKIA[0-9A-Z]{16}|-----BEGIN )`)
)

// Finding is one source match or a refusal.
type Finding struct {
	Path    string
	Rule    string
	Line    int
	Detail  string
	Refused bool
}

// ScanFile checks one source file. Unsupported extensions return a refusal
// only when the caller asked to scan a non-source path. Callers that filter
// by extension will not see that.
func ScanFile(path string) []Finding {
	ext := strings.ToLower(filepath.Ext(path))
	rules, ok := rulesFor(ext)
	if !ok {
		return []Finding{{Path: path, Rule: "unsupported", Detail: errNotSource.Error(), Refused: true}}
	}
	f, err := openRegular(path)
	if err != nil {
		return []Finding{{Path: path, Rule: "refused", Detail: err.Error(), Refused: true}}
	}
	defer f.Close()

	sc := bufio.NewScanner(io.LimitReader(f, maxSourceBytes+1))
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	var out []Finding
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "*") {
			continue
		}
		for _, rule := range rules {
			if rule.re.MatchString(line) {
				out = append(out, Finding{
					Path:   path,
					Rule:   rule.id,
					Line:   lineNo,
					Detail: redact(clip(trim, 180)),
				})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return []Finding{{Path: path, Rule: "refused", Detail: err.Error(), Refused: true}}
	}
	return out
}

type rule struct {
	id string
	re *regexp.Regexp
}

func rulesFor(ext string) ([]rule, bool) {
	switch ext {
	case ".go":
		return []rule{
			{"go-insecure-tls", regexp.MustCompile(`InsecureSkipVerify\s*[:=]+\s*true`)},
			{"go-sql-sprintf", regexp.MustCompile(`\.(Exec|Query|QueryRow)\(\s*fmt\.Sprintf`)},
			{"go-shell", regexp.MustCompile(`exec\.Command\(\s*"(sh|bash|zsh)"`)},
		}, true
	case ".py":
		return []rule{
			{"py-shell-true", regexp.MustCompile(`shell\s*=\s*True`)},
			{"py-os-system", regexp.MustCompile(`os\.system\s*\(`)},
			{"py-pickle", regexp.MustCompile(`pickle\.loads\s*\(`)},
			{"py-eval", regexp.MustCompile(`(^|[^.\w])eval\s*\(`)},
		}, true
	case ".js":
		return []rule{
			{"js-eval", regexp.MustCompile(`(^|[^.\w])eval\s*\(`)},
			{"js-child-exec", regexp.MustCompile(`child_process\.exec\s*\(|\.exec\(\s*['"]`)},
			{"js-html", regexp.MustCompile(`dangerouslySetInnerHTML`)},
		}, true
	case ".java":
		return []rule{
			{"java-runtime-exec", regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\s*\(`)},
			{"java-sql-concat", regexp.MustCompile(`\.execute(Update|Query)?\(\s*[^)]*\+`)},
		}, true
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp":
		return []rule{
			{"c-gets", regexp.MustCompile(`\bgets\s*\(`)},
			{"c-strcpy", regexp.MustCompile(`\bstrcpy\s*\(`)},
			{"c-sprintf", regexp.MustCompile(`\bsprintf\s*\(`)},
			{"c-system", regexp.MustCompile(`\bsystem\s*\(`)},
		}, true
	case ".sh", ".bash":
		return []rule{
			{"sh-pipe-shell", regexp.MustCompile(`(curl|wget)\b[^|\n]*\|\s*(sh|bash)\b`)},
			{"sh-eval", regexp.MustCompile(`\beval\b`)},
		}, true
	default:
		return nil, false
	}
}

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maxSourceBytes {
		return nil, errOversize
	}
	return os.Open(path)
}

func redact(s string) string {
	return secretVal.ReplaceAllString(s, "[redacted]")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
