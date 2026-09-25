package exposure

import "testing"

func TestUnknownIsNotHealthy(t *testing.T) {
	report := Collect("darwin", func(name string, args ...string) (string, bool) {
		if name == "/usr/libexec/ApplicationFirewall/socketfilterfw" {
			return "Firewall is disabled. (State = 0)", true
		}
		return "", false
	})
	if report.Decision != Fail {
		t.Fatalf("decision %s", report.Decision)
	}
	quiet := Collect("linux", func(string, ...string) (string, bool) { return "", false })
	if quiet.Decision != Unknown {
		t.Fatalf("missing tools decided %s", quiet.Decision)
	}
	if Collect("plan9", CommandRunner).Decision != Unknown {
		t.Fatal("unknown platform passed")
	}
}

func TestParsersAreExact(t *testing.T) {
	linux := Collect("linux", func(name string, _ ...string) (string, bool) {
		switch name {
		case "/usr/sbin/ufw":
			return "Status: active\nLogging: on", true
		case "/usr/bin/lsblk":
			return "disk\ncrypt\npart", true
		case "/usr/bin/gsettings":
			return "true", true
		case "/usr/bin/apt-config":
			return "Enabled='1'", true
		case "/usr/bin/systemctl":
			return "disabled", true
		default:
			return "Status: active", true
		}
	})
	if linux.Decision != Pass {
		t.Fatalf("%+v", linux)
	}
	tricked := Collect("linux", func(string, ...string) (string, bool) {
		return "Status: inactive but Status: active", true
	})
	if tricked.Decision == Pass {
		t.Fatal("substring firewall answer passed")
	}
	windows := Collect("windows", func(name string, _ ...string) (string, bool) {
		if name == "windows-firewall" {
			return "false", true
		}
		return "true", true
	})
	if windows.Decision != Fail {
		t.Fatalf("windows %+v", windows)
	}
}
