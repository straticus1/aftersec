//go:build darwin

package selfprotect

import "io"

// Endpoint Security AUTH_OPEN enforcement is attached by pkg/edr.
func StartNativeGuard([]string, string) (io.Closer, error) { return nil, nil }
