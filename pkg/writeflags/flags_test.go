package writeflags

import "testing"

func TestRestrictDeniesUserAndMonitorWatchesTheTree(t *testing.T) {
	set, err := Load([]Spec{
		{Path: "/usr/local", Mode: ModeMonitor},
		{Path: "/usr/local/bin", Mode: ModeRestrict, AllowUIDs: []uint32{0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	user := set.Apply([]string{"/usr/local/bin/tool"}, 501)
	if user.Effect != EffectDeny || user.FlagPath != "/usr/local/bin" {
		t.Fatalf("%+v", user)
	}
	root := set.Apply([]string{"/usr/local/bin/tool"}, 0)
	if root.Effect != EffectMonitor || root.FlagPath != "/usr/local" {
		t.Fatalf("root install: %+v", root)
	}
	exempt, err := Load([]Spec{{Path: "/usr/local/bin", Mode: ModeRestrict, AllowUIDs: []uint32{0}}})
	if err != nil {
		t.Fatal(err)
	}
	if exempt.Apply([]string{"/usr/local/bin/tool"}, 0).Effect != EffectNone {
		t.Fatal("allowed uid was still denied")
	}
	watched := set.Apply([]string{"/usr/local/share/man"}, 501)
	if watched.Effect != EffectMonitor || watched.FlagPath != "/usr/local" {
		t.Fatalf("%+v", watched)
	}
	if set.Apply([]string{"/usr/local-evil/bin"}, 501).Effect != EffectNone {
		t.Fatal("prefix collision matched")
	}
	escaped := set.Apply([]string{"/tmp/link", "/usr/local/bin/tool"}, 501)
	if escaped.Effect != EffectDeny {
		t.Fatalf("resolved path: %+v", escaped)
	}
}

func TestLoadRejectsBroadAndAmbiguousFlags(t *testing.T) {
	for _, spec := range []Spec{
		{Path: "usr/local/bin", Mode: ModeRestrict},
		{Path: "/usr/local/../bin", Mode: ModeRestrict},
		{Path: "/", Mode: ModeRestrict},
		{Path: "/usr/local", Mode: "watch"},
		{Path: "/usr/local", Mode: ModeMonitor, AllowUIDs: []uint32{0}},
	} {
		if _, err := Load([]Spec{spec}); err == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	if _, err := Load([]Spec{
		{Path: "/usr/local/bin/", Mode: ModeRestrict},
		{Path: "/usr/local/bin", Mode: ModeMonitor},
	}); err == nil {
		t.Fatal("duplicate path accepted")
	}
	empty, err := Load(nil)
	if err != nil || empty.Apply([]string{"/usr/local/bin"}, 501).Effect != EffectNone {
		t.Fatal(err)
	}
	locked, err := Load([]Spec{{Path: "/usr/local/bin", Mode: ModeRestrict}})
	if err != nil {
		t.Fatal(err)
	}
	if locked.Apply([]string{"/usr/local/bin/tool"}, 0).Effect != EffectDeny {
		t.Fatal("empty allow list permitted root")
	}
}
