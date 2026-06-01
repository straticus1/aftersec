//go:build linux

package tuning

import "errors"

func InstallFinderExtension() error {
	return errors.New("Finder extension not available on Linux")
}
