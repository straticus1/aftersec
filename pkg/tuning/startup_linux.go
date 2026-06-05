//go:build linux

package tuning

import (
	"aftersec/pkg/core"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type StartupItem struct {
	Name     string
	Path     string
	IsSystem bool
}

func GetStartupItems() ([]StartupItem, error) {
	var items []StartupItem

	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") || strings.Contains(e.Name(), "@") {
				continue
			}
			items = append(items, StartupItem{
				Name:     strings.TrimSuffix(e.Name(), ".service"),
				Path:     filepath.Join(dir, e.Name()),
				IsSystem: true,
			})
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		userDir := filepath.Join(home, ".config/systemd/user")
		entries, _ := os.ReadDir(userDir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			items = append(items, StartupItem{
				Name:     strings.TrimSuffix(e.Name(), ".service"),
				Path:     filepath.Join(userDir, e.Name()),
				IsSystem: false,
			})
		}
	}

	return items, nil
}

func DisableStartupItem(item StartupItem) error {
	if item.IsSystem {
		script := fmt.Sprintf("systemctl disable --now %s", item.Name)
		core.RegisterAllowedScript(script)
		return core.RunPrivileged(script)
	}
	return exec.Command("systemctl", "--user", "disable", "--now", item.Name).Run()
}
