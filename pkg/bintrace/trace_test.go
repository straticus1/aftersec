package bintrace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScoreInjectionChain(t *testing.T) {
	report := Report{
		Symbols: []string{"_task_for_pid", "_mach_vm_write"},
	}
	score(&report)
	if report.Verdict != "suspicious" {
		t.Fatalf("%#v", report)
	}
}

func TestScoreNoIndicatorIsNotABenignClaim(t *testing.T) {
	report := Report{Symbols: []string{"_printf"}}
	score(&report)
	if report.Verdict != "no-indicator" {
		t.Fatalf("%#v", report)
	}
	if report.Reason == "" {
		t.Fatal("missing reason")
	}
}

func TestInspectRefusesSymlinkAndOversize(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("not a binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	got := Inspect(link)
	if got.Verdict != "refused" || got.Reason != "symlink refused" {
		t.Fatalf("%#v", got)
	}

	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBinaryBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got = Inspect(big)
	if got.Verdict != "refused" || got.Reason != "binary exceeds 32 MiB" {
		t.Fatalf("%#v", got)
	}
}

func TestInspectTextIsRefusedNotClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Inspect(path)
	if got.Verdict != "refused" {
		t.Fatalf("text file looked analyzed: %#v", got)
	}
}
