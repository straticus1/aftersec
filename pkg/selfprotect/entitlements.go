package selfprotect

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"howett.net/plist"
)

// ParseEntitlementKeys reads a codesign entitlement plist and returns the keys
// whose value is boolean true. A missing plist or a non-boolean value is not
// treated as a held entitlement.
//
// Threats: a revoked or stripped signing entitlement must not look present.
// This parser does not prove Apple issued the signature.
func ParseEntitlementKeys(output []byte) ([]string, error) {
	start := bytes.Index(output, []byte("<plist"))
	if start < 0 || len(output) > 1<<20 {
		return nil, fmt.Errorf("entitlement plist is missing or too large")
	}
	var raw map[string]any
	if _, err := plist.Unmarshal(output[start:], &raw); err != nil {
		return nil, fmt.Errorf("parse entitlement plist: %w", err)
	}
	keys := make([]string, 0, len(raw))
	for key, value := range raw {
		held, ok := value.(bool)
		if key == "" || !ok || !held {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

// CheckProcessEntitlements compares the running binary with the entitlements
// this platform requires. Platforms without an embedded entitlement set return
// nil. A read failure or a missing required key is an error.
func CheckProcessEntitlements(ctx context.Context, executable string) error {
	required := platformEntitlements()
	if len(required) == 0 {
		return nil
	}
	observed, err := readEntitlementKeys(ctx, executable)
	if err != nil {
		return err
	}
	return EntitlementsRevoked(required, observed)
}
