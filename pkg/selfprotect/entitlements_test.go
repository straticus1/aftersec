package selfprotect

import "testing"

func TestParseEntitlementKeysRequiresBooleanTrue(t *testing.T) {
	raw := []byte("Executable=/x\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>com.apple.developer.endpoint-security.client</key><true/><key>com.example.unused</key><false/><key>not-a-bool</key><string>x</string></dict></plist>")
	keys, err := ParseEntitlementKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "com.apple.developer.endpoint-security.client" {
		t.Fatalf("%v", keys)
	}
	if err := EntitlementsRevoked([]string{"com.apple.developer.endpoint-security.client"}, keys); err != nil {
		t.Fatal(err)
	}
	if err := EntitlementsRevoked([]string{"com.apple.developer.endpoint-security.client"}, nil); err != ErrEntitlementRevoked {
		t.Fatalf("revoked set: %v", err)
	}
}

func TestParseEntitlementKeysRejectsMissingPlist(t *testing.T) {
	if _, err := ParseEntitlementKeys([]byte("not a plist")); err == nil {
		t.Fatal("accepted missing plist")
	}
	if _, err := ParseEntitlementKeys(make([]byte, 1<<20+1)); err == nil {
		t.Fatal("accepted oversized output")
	}
}
