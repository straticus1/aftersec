package bintrace

import "testing"

func TestResolveRpathAndWritable(t *testing.T) {
	got := Resolve("/Apps/Demo.app/Contents/MacOS/Demo", "@rpath/libHelper.dylib", []string{
		"@executable_path/../Frameworks",
		"/tmp/evil",
	})
	if len(got) != 2 {
		t.Fatalf("%#v", got)
	}
	if !writablePath("/tmp/evil/libHelper.dylib") {
		t.Fatal("tmp candidate should be writable")
	}
	if writablePath("/usr/lib/libSystem.B.dylib") {
		t.Fatal("system library marked writable")
	}
}

func TestReducePromotesSignatureMismatchOnly(t *testing.T) {
	d := Dossier{
		State: "signed",
		Team:  "HOSTTEAM",
		Libraries: []Library{{
			InstallName: "@rpath/libHelper.dylib",
			Resolved:    []string{"/Users/a/libHelper.dylib"},
			Writable:    true,
			State:       "unsigned",
		}},
	}
	dec := Reduce(d)
	if !dec.Promote || len(dec.Hard) == 0 {
		t.Fatalf("%#v", dec)
	}
}

func TestReduceDoesNotPromoteOneWeakSignal(t *testing.T) {
	d := Dossier{
		State: "signed",
		Team:  "HOSTTEAM",
		Libraries: []Library{{
			InstallName: "/usr/lib/libSystem.B.dylib",
			Resolved:    []string{"/usr/lib/libSystem.B.dylib"},
			State:       "distro",
		}},
	}
	dec := Reduce(d)
	if dec.Promote || dec.Score != 0 {
		t.Fatalf("system library promoted: %#v", dec)
	}
}

func TestReduceTwoWeakSignalsPromote(t *testing.T) {
	d := Dossier{
		State: "signed",
		Team:  "HOSTTEAM",
		Libraries: []Library{
			{InstallName: "liba.dylib", Missing: true},
			{InstallName: "libb.dylib", Missing: true},
		},
	}
	dec := Reduce(d)
	if !dec.Promote || len(dec.Hard) != 0 {
		t.Fatalf("%#v", dec)
	}
}

func TestShouldCollectSkipsSystemUnlessAgent(t *testing.T) {
	if ShouldCollect("/bin/zsh", "/bin/ls") {
		t.Fatal("system exec collected")
	}
	if !ShouldCollect("/Applications/Cursor.app/Contents/MacOS/Cursor", "/bin/ls") {
		t.Fatal("agent child skipped")
	}
	if !ShouldCollect("/bin/zsh", "/tmp/payload") {
		t.Fatal("non-system exec skipped")
	}
}
