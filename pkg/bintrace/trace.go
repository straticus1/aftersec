// Package bintrace reads Mach-O, ELF, and PE imports and linked libraries.
//
// Threats: a hostile file can be truncated, oversized, or a symlink to a
// different inode. Those are refused and are not "clean". A suspicious import
// chain is evidence, not proof of malice. No suspicious import is not proof
// the file is benign: packing, runtime dlopen, and inlined syscalls are invisible
// here. This package never executes the file.
package bintrace

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"io"
	"os"
	"strings"
)

const maxBinaryBytes int64 = 32 << 20

var (
	errSymlink    = errors.New("symlink refused")
	errNotRegular = errors.New("not a regular file")
	errOversize   = errors.New("binary exceeds 32 MiB")
	errNotBinary  = errors.New("not a mach-o, elf, or pe file")
)

// Report is the static import trace of one file.
type Report struct {
	Path       string
	Format     string
	Libraries  []string
	Symbols    []string
	Indicators []string
	Verdict    string // refused, no-indicator, suspicious
	Reason     string
}

// Inspect parses path and scores its import chain. A refused report has Verdict
// "refused" and Reason set. Callers must not treat "no-indicator" as benign.
func Inspect(path string) Report {
	report := Report{Path: path, Verdict: "refused"}
	f, err := openRegular(path)
	if err != nil {
		report.Reason = err.Error()
		return report
	}
	defer f.Close()

	if fat, err := macho.NewFatFile(f); err == nil {
		defer fat.Close()
		report.Format = "mach-o-fat"
		for _, arch := range fat.Arches {
			libs, syms := machoImports(arch.File)
			report.Libraries = append(report.Libraries, libs...)
			report.Symbols = append(report.Symbols, syms...)
		}
		score(&report)
		return report
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		report.Reason = err.Error()
		return report
	}
	if m, err := macho.NewFile(f); err == nil {
		defer m.Close()
		report.Format = "mach-o"
		report.Libraries, report.Symbols = machoImports(m)
		score(&report)
		return report
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		report.Reason = err.Error()
		return report
	}
	if e, err := elf.NewFile(f); err == nil {
		defer e.Close()
		report.Format = "elf"
		report.Libraries, report.Symbols = elfImports(e)
		score(&report)
		return report
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		report.Reason = err.Error()
		return report
	}
	if p, err := pe.NewFile(f); err == nil {
		defer p.Close()
		report.Format = "pe"
		report.Symbols = peImports(p)
		score(&report)
		return report
	}
	report.Reason = errNotBinary.Error()
	return report
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
		return nil, errNotRegular
	}
	if info.Size() > maxBinaryBytes {
		return nil, errOversize
	}
	return os.Open(path)
}

func machoImports(m *macho.File) (libs, syms []string) {
	if m == nil {
		return nil, nil
	}
	if l, err := m.ImportedLibraries(); err == nil {
		libs = append(libs, l...)
	}
	if s, err := m.ImportedSymbols(); err == nil {
		syms = append(syms, s...)
	}
	return libs, syms
}

func elfImports(e *elf.File) (libs, syms []string) {
	if e == nil {
		return nil, nil
	}
	if l, err := e.ImportedLibraries(); err == nil {
		libs = append(libs, l...)
	}
	if s, err := e.ImportedSymbols(); err == nil {
		for _, sym := range s {
			syms = append(syms, sym.Name)
		}
	}
	return libs, syms
}

func peImports(p *pe.File) []string {
	if p == nil {
		return nil
	}
	syms, err := p.ImportedSymbols()
	if err != nil {
		return nil
	}
	return append([]string(nil), syms...)
}

// chains are import combinations that are used by process injection and
// credential access. One hit is suspicious. None is not a clean bill.
var chains = []struct {
	name  string
	needs []string
}{
	{"macos task port and memory write", []string{"task_for_pid", "mach_vm_write"}},
	{"macos thread inject", []string{"thread_create_running", "thread_set_state"}},
	{"remote process inject", []string{"virtualallocex", "writeprocessmemory", "createremotethread"}},
	{"process hollowing", []string{"ntunmapviewofsection", "writeprocessmemory"}},
	{"linux remote memory", []string{"process_vm_writev", "ptrace"}},
	{"linux memfd execute", []string{"memfd_create", "execveat"}},
}

var singleSignals = []string{
	"task_for_pid",
	"authorizationexecutewithprivileges",
	"seckeychainfindgenericpassword",
	"ptrace",
	"process_vm_readv",
	"memfd_create",
	"createremotethread",
	"virtualallocex",
}

func score(report *Report) {
	have := map[string]bool{}
	for _, item := range append(append([]string{}, report.Libraries...), report.Symbols...) {
		have[strings.ToLower(item)] = true
		for _, part := range strings.FieldsFunc(strings.ToLower(item), func(r rune) bool {
			return r == '_' || r == '.' || r == ':' || r == ' ' || r == '@'
		}) {
			if part != "" {
				have[part] = true
			}
		}
	}
	for _, chain := range chains {
		if hasAll(have, chain.needs) {
			report.Indicators = append(report.Indicators, chain.name)
		}
	}
	for _, sig := range singleSignals {
		if hasSymbol(have, sig) {
			report.Indicators = append(report.Indicators, sig)
		}
	}
	if len(report.Indicators) > 0 {
		report.Verdict = "suspicious"
		report.Reason = strings.Join(report.Indicators, ", ")
		return
	}
	report.Verdict = "no-indicator"
	report.Reason = "no injection or credential-import chain in the static import table"
}

func hasAll(have map[string]bool, needs []string) bool {
	for _, n := range needs {
		if !hasSymbol(have, n) {
			return false
		}
	}
	return true
}

func hasSymbol(have map[string]bool, name string) bool {
	name = strings.ToLower(name)
	if have[name] {
		return true
	}
	for got := range have {
		if strings.Contains(got, name) {
			return true
		}
	}
	return false
}
