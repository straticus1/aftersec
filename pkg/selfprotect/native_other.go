//go:build !darwin && !linux

package selfprotect

import (
	"fmt"
	"io"
)

func StartNativeGuard([]string, string) (io.Closer, error) {
	return nil, fmt.Errorf("native self-protection is unsupported")
}
