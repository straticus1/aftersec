//go:build !darwin

package selfprotect

import "context"

func platformEntitlements() []string { return nil }

func readEntitlementKeys(context.Context, string) ([]string, error) {
	return nil, ErrInvalidStopPolicy
}
