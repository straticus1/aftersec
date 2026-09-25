// Package accord checks that one execution agrees with itself.
//
// Threats: a swapped binary, a symlink, an oversized file, a missing hash, or a
// malformed agent config must not look like agreement. Accord never executes
// the file and never treats "no finding" as proof the program is benign. PID
// reuse can make a dead process look alive for one observation. Load drift
// compares a mapped library to the static import table from the last successful
// trace of that path; it does not see libraries loaded before that trace.
package accord

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"aftersec/pkg/agentinventory"
	"aftersec/pkg/bintrace"
)

const maxHashBytes int64 = 32 << 20

const (
	KindContractBreak = "contract-break"
	KindIdentityDrift = "identity-drift"
	KindLoadDrift     = "load-drift"
	KindRefused       = "refused"
)

// Exec is one process start the kernel already allowed.
type Exec struct {
	PID        int
	Path       string
	ParentPath string
	Home       string
}

// Observation is a disagreement or a failed check. Agreement returns no observations.
type Observation struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Parent string `json:"parent,omitempty"`
	Detail string `json:"detail"`
}

type stamp struct {
	hash string
	pid  int
	libs map[string]bool
}

// Engine remembers the last hash and import table for each path.
type Engine struct {
	mu    sync.Mutex
	seen  map[string]stamp
	alive func(pid int) bool
	order []string
}

// NewEngine returns an engine that uses syscall.Kill(pid, 0) to test liveness.
func NewEngine() *Engine {
	return &Engine{seen: map[string]stamp{}, alive: pidAlive}
}

// Observe compares this exec to the agent contract and to the last hash of path.
func (e *Engine) Observe(ex Exec) []Observation {
	if e.alive == nil {
		e.alive = pidAlive
	}
	var out []Observation
	path := filepath.Clean(ex.Path)
	if path == "" || path == "." {
		return []Observation{{Kind: KindRefused, Path: ex.Path, Detail: "empty exec path"}}
	}
	if agent := agentOf(ex.ParentPath); agent != "" {
		cmds, derr := agentinventory.Declared(ex.Home)
		if derr != nil {
			out = append(out, Observation{Kind: KindRefused, Path: path, Parent: ex.ParentPath, Detail: derr.Error()})
		} else if !declared(agent, cmds) {
			out = append(out, Observation{Kind: KindRefused, Path: path, Parent: ex.ParentPath, Detail: "no declared command for " + agent})
		} else if !matches(path, agent, cmds) {
			out = append(out, Observation{Kind: KindContractBreak, Path: path, Parent: ex.ParentPath, Detail: agent + " ran " + filepath.Base(path)})
		}
	}
	sum, err := hashFile(path)
	if err != nil {
		out = append(out, Observation{Kind: KindRefused, Path: path, Parent: ex.ParentPath, Detail: err.Error()})
		return out
	}
	report := bintrace.Inspect(path)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seen == nil {
		e.seen = map[string]stamp{}
	}
	prev, ok := e.seen[path]
	if ok && prev.hash != sum && e.alive(prev.pid) {
		out = append(out, Observation{Kind: KindIdentityDrift, Path: path, Detail: "bytes changed while pid " + strconv.Itoa(prev.pid) + " is alive"})
	}
	next := stamp{hash: sum, pid: ex.PID, libs: prev.libs}
	if report.Verdict != "refused" {
		next.libs = libSet(report.Libraries)
	}
	if !ok {
		e.order = append(e.order, path)
	}
	e.seen[path] = next
	e.trim()
	return out
}

// ObserveMap reports a library mapped for path that was not in the last static import table.
func (e *Engine) ObserveMap(path, mapped string) []Observation {
	path = filepath.Clean(path)
	base := strings.ToLower(filepath.Base(mapped))
	if path == "" || path == "." || base == "" || base == "." {
		return []Observation{{Kind: KindRefused, Path: path, Detail: "empty map observation"}}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prev, ok := e.seen[path]
	if !ok || prev.libs == nil {
		return []Observation{{Kind: KindRefused, Path: path, Detail: "no import baseline"}}
	}
	if prev.libs[base] {
		return nil
	}
	return []Observation{{Kind: KindLoadDrift, Path: path, Detail: base + " was not in the static import table"}}
}

func (e *Engine) trim() {
	const capN = 4096
	for len(e.order) > capN {
		drop := e.order[0]
		e.order = e.order[1:]
		delete(e.seen, drop)
	}
}

func declared(agent string, cmds []agentinventory.Command) bool {
	for _, c := range cmds {
		if c.Agent == agent && c.Path != "" {
			return true
		}
	}
	return false
}

func matches(child, agent string, cmds []agentinventory.Command) bool {
	base := strings.ToLower(filepath.Base(child))
	for _, c := range cmds {
		if c.Agent != agent || c.Path == "" {
			continue
		}
		if strings.EqualFold(filepath.Base(c.Path), base) || strings.EqualFold(c.Path, child) {
			return true
		}
	}
	return false
}

func agentOf(parent string) string {
	switch strings.ToLower(filepath.Base(parent)) {
	case "claude", "claude-code":
		return "claude"
	case "cursor":
		return "cursor"
	case "codex":
		return "codex"
	case "code":
		return "vscode"
	case "goose":
		return "goose"
	case "gemini":
		return "gemini"
	default:
		return ""
	}
}

func libSet(libs []string) map[string]bool {
	out := map[string]bool{}
	for _, lib := range libs {
		base := strings.ToLower(filepath.Base(lib))
		if base != "" {
			out[base] = true
		}
	}
	return out
}

func hashFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("symlink refused")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if info.Size() > maxHashBytes {
		return "", errors.New("file exceeds 32 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxHashBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxHashBytes {
		return "", errors.New("file exceeds 32 MiB")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// HomeForUID resolves the home directory of the user who started the process.
func HomeForUID(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(u.HomeDir) == "" {
		return "", errors.New("empty home")
	}
	return u.HomeDir, nil
}
