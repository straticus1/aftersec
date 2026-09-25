package codescan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoTLSAndSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	secret := "sk-ant-do-not-leak-this-token"
	path := filepath.Join(dir, "client.go")
	body := "package p\nfunc f() {\ntr.InsecureSkipVerify = true // " + secret + "\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ScanFile(path)
	if len(got) != 1 || got[0].Refused || got[0].Rule != "go-insecure-tls" {
		t.Fatalf("%#v", got)
	}
	if strings.Contains(got[0].Detail, secret) || strings.Contains(got[0].Detail, "sk-ant-") {
		t.Fatalf("secret leaked: %s", got[0].Detail)
	}
}

func TestPythonShellAndCleanFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "a.py")
	if err := os.WriteFile(bad, []byte("import subprocess\nsubprocess.run(cmd, shell=True)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ScanFile(bad)
	if len(got) != 1 || got[0].Rule != "py-shell-true" {
		t.Fatalf("%#v", got)
	}
	good := filepath.Join(dir, "b.py")
	if err := os.WriteFile(good, []byte("def add(a, b):\n    return a + b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got = ScanFile(good)
	if len(got) != 0 {
		t.Fatalf("clean file flagged: %#v", got)
	}
}

func TestSymlinkAndOversizeRefuse(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(real, []byte("curl http://x | sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got := ScanFile(link)
	if len(got) != 1 || !got[0].Refused {
		t.Fatalf("%#v", got)
	}
	big := filepath.Join(dir, "big.py")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSourceBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got = ScanFile(big)
	if len(got) != 1 || !got[0].Refused || got[0].Detail != errOversize.Error() {
		t.Fatalf("%#v", got)
	}
}

func TestShellPipeAndCGets(t *testing.T) {
	dir := t.TempDir()
	sh := filepath.Join(dir, "i.sh")
	if err := os.WriteFile(sh, []byte("curl https://example | bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ScanFile(sh)
	if len(got) != 1 || got[0].Rule != "sh-pipe-shell" {
		t.Fatalf("%#v", got)
	}
	c := filepath.Join(dir, "a.c")
	if err := os.WriteFile(c, []byte("int main(){ gets(buf); }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got = ScanFile(c)
	if len(got) != 1 || got[0].Rule != "c-gets" {
		t.Fatalf("%#v", got)
	}
}
