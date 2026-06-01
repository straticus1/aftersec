//go:build linux

package tuning

import "errors"

type StartupItem struct {
	Name     string
	Path     string
	IsSystem bool
}

func GetStartupItems() ([]StartupItem, error) {
	return nil, errors.New("LaunchAgents/Daemons not available on Linux")
}

func DisableStartupItem(_ StartupItem) error {
	return errors.New("startup items not available on Linux")
}
