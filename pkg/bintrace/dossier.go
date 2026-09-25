package bintrace

import (
	"debug/elf"
	"debug/macho"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxLibraryDepth = 2
	maxLibraries    = 24
)

// Library is one linked dependency and the files that name can resolve to.
type Library struct {
	InstallName string   `json:"install_name"`
	Resolved    []string `json:"resolved,omitempty"`
	Writable    bool     `json:"writable,omitempty"`
	Ambiguous   bool     `json:"ambiguous,omitempty"`
	Missing     bool     `json:"missing,omitempty"`
	State       string   `json:"state,omitempty"`
	Team        string   `json:"team,omitempty"`
}

// Dossier is the facts collected for one binary and its direct libraries.
// It is not a malware verdict.
type Dossier struct {
	Path       string    `json:"path"`
	Format     string    `json:"format"`
	State      string    `json:"state"`
	Team       string    `json:"team,omitempty"`
	Rpaths     []string  `json:"rpaths,omitempty"`
	Libraries  []Library `json:"libraries,omitempty"`
	Indicators []string  `json:"indicators,omitempty"`
	Unknown    []string  `json:"unknown,omitempty"`
	Err        string    `json:"err,omitempty"`
}

// Decision is the on-host score. Promote is the only gate into the swarm.
type Decision struct {
	Score   int      `json:"score"`
	Promote bool     `json:"promote"`
	Hard    []string `json:"hard,omitempty"`
	Weak    []string `json:"weak,omitempty"`
}

// ShouldCollect reports whether this exec is worth a library walk.
// System binaries are skipped unless a known agent started them.
func ShouldCollect(parent, path string) bool {
	if agentParent(parent) {
		return true
	}
	return !trustedPath(path)
}

// Collect walks the binary's declared libraries. An unreadable file is recorded
// in Unknown and is not treated as clean.
func Collect(path string) Dossier {
	d := Dossier{Path: path}
	seen := map[string]bool{}
	collectInto(&d, path, 0, seen)
	return d
}

func collectInto(d *Dossier, path string, depth int, seen map[string]bool) {
	if len(d.Libraries) >= maxLibraries || depth > maxLibraryDepth {
		return
	}
	clean := filepath.Clean(path)
	if seen[clean] {
		return
	}
	seen[clean] = true
	report := Inspect(clean)
	if report.Verdict == "refused" && report.Format == "" {
		if depth == 0 {
			d.Err = report.Reason
		} else {
			d.Unknown = append(d.Unknown, filepath.Base(clean)+": "+report.Reason)
		}
		return
	}
	if depth == 0 {
		d.Format = report.Format
		d.Indicators = append(d.Indicators, report.Indicators...)
		d.State, d.Team = lookupSignature(clean)
	}
	libs, rpaths := declaredLibs(clean)
	if depth == 0 {
		d.Rpaths = rpaths
	}
	for _, name := range libs {
		if len(d.Libraries) >= maxLibraries {
			return
		}
		cands := existing(Resolve(clean, name, rpaths))
		lib := Library{InstallName: name, Resolved: cands}
		if len(cands) == 0 {
			lib.Missing = true
			d.Libraries = append(d.Libraries, lib)
			continue
		}
		if len(cands) > 1 {
			lib.Ambiguous = true
		}
		for _, c := range cands {
			if writablePath(c) {
				lib.Writable = true
			}
		}
		lib.State, lib.Team = lookupSignature(cands[0])
		d.Libraries = append(d.Libraries, lib)
		if !trustedPath(cands[0]) {
			collectInto(d, cands[0], depth+1, seen)
		}
	}
}

// Reduce scores a dossier. A hard signal promotes it. Two weak signals promote it.
// No signal does not mean the file is benign.
func Reduce(d Dossier) Decision {
	var dec Decision
	if d.Err != "" {
		dec.Weak = append(dec.Weak, "binary unreadable")
		dec.Score++
	}
	hostSigned := d.State == "signed" && d.Team != ""
	for _, lib := range d.Libraries {
		base := filepath.Base(lib.InstallName)
		if lib.Missing {
			dec.Weak = append(dec.Weak, base+" unresolved")
			dec.Score++
		}
		if lib.Ambiguous && lib.Writable {
			dec.Hard = append(dec.Hard, base+" resolves to multiple files including a writable path")
			dec.Score += 5
		} else if lib.Writable {
			dec.Weak = append(dec.Weak, base+" resolves into a writable directory")
			dec.Score++
		}
		if hostSigned && !trustedInstall(lib.InstallName) {
			switch lib.State {
			case "unsigned", "adhoc":
				dec.Hard = append(dec.Hard, base+" is "+lib.State+" inside a signed host")
				dec.Score += 5
			case "signed":
				if lib.Team != "" && lib.Team != d.Team {
					dec.Hard = append(dec.Hard, base+" team "+lib.Team+" does not match host "+d.Team)
					dec.Score += 5
				}
			case "unknown":
				dec.Weak = append(dec.Weak, base+" signature unknown")
				dec.Score++
			}
		}
	}
	for _, ind := range d.Indicators {
		dec.Hard = append(dec.Hard, ind)
		dec.Score += 5
	}
	for _, u := range d.Unknown {
		dec.Weak = append(dec.Weak, u)
		dec.Score++
	}
	dec.Promote = len(dec.Hard) > 0 || dec.Score >= 2
	return dec
}

// Resolve expands an install name against the binary's directory and rpaths.
func Resolve(origin, name string, rpaths []string) []string {
	name = strings.TrimSpace(name)
	switch {
	case strings.HasPrefix(name, "@rpath/"):
		rest := strings.TrimPrefix(name, "@rpath/")
		var out []string
		for _, r := range rpaths {
			out = append(out, filepath.Clean(expandRoot(origin, r)+"/"+rest))
		}
		return unique(out)
	case strings.HasPrefix(name, "@executable_path/"):
		return []string{filepath.Clean(filepath.Dir(origin) + "/" + strings.TrimPrefix(name, "@executable_path/"))}
	case strings.HasPrefix(name, "@loader_path/"):
		return []string{filepath.Clean(filepath.Dir(origin) + "/" + strings.TrimPrefix(name, "@loader_path/"))}
	case strings.HasPrefix(name, "/"):
		return []string{filepath.Clean(name)}
	case name == "":
		return nil
	default:
		return []string{filepath.Clean(filepath.Dir(origin) + "/" + name)}
	}
}

func expandRoot(origin, rpath string) string {
	switch {
	case strings.HasPrefix(rpath, "@executable_path"):
		return filepath.Dir(origin) + strings.TrimPrefix(rpath, "@executable_path")
	case strings.HasPrefix(rpath, "@loader_path"):
		return filepath.Dir(origin) + strings.TrimPrefix(rpath, "@loader_path")
	default:
		return rpath
	}
}

func declaredLibs(path string) (libs, rpaths []string) {
	f, err := openRegular(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	if fat, err := macho.NewFatFile(f); err == nil {
		defer fat.Close()
		if len(fat.Arches) > 0 {
			return machoDecls(fat.Arches[0].File)
		}
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, nil
	}
	if m, err := macho.NewFile(f); err == nil {
		defer m.Close()
		return machoDecls(m)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, nil
	}
	if e, err := elf.NewFile(f); err == nil {
		defer e.Close()
		if needed, err := e.ImportedLibraries(); err == nil {
			libs = needed
		}
		if rp, err := e.DynString(elf.DT_RPATH); err == nil {
			rpaths = append(rpaths, splitSearch(rp)...)
		}
		if rp, err := e.DynString(elf.DT_RUNPATH); err == nil {
			rpaths = append(rpaths, splitSearch(rp)...)
		}
		return libs, rpaths
	}
	return nil, nil
}

func machoDecls(m *macho.File) (libs, rpaths []string) {
	if m == nil {
		return nil, nil
	}
	for _, load := range m.Loads {
		switch c := load.(type) {
		case *macho.Dylib:
			libs = append(libs, c.Name)
		case *macho.Rpath:
			rpaths = append(rpaths, c.Path)
		}
	}
	return libs, rpaths
}

func existing(paths []string) []string {
	var out []string
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, p)
	}
	return out
}

func writablePath(path string) bool {
	p := strings.ToLower(path)
	if trustedPath(p) {
		return false
	}
	for _, pre := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/users/", "/home/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func trustedPath(path string) bool {
	p := strings.ToLower(path)
	for _, pre := range []string{"/usr/", "/bin/", "/sbin/", "/system/", "/lib/", "/lib64/", "/library/apple/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func trustedInstall(name string) bool {
	return trustedPath(name) || strings.HasPrefix(name, "/System/") || strings.HasPrefix(name, "/usr/")
}

func agentParent(parent string) bool {
	switch strings.ToLower(filepath.Base(parent)) {
	case "claude", "claude-code", "cursor", "codex", "code", "goose", "gemini":
		return true
	default:
		return false
	}
}

func splitSearch(paths []string) []string {
	var out []string
	for _, p := range paths {
		for _, part := range strings.Split(p, ":") {
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
