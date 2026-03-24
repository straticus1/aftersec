package tuning

import (
	"aftersec/pkg/core"
	"fmt"
	"os"
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

	dirs := []struct {
		path     string
		isSystem bool
	}{
		{"/Library/LaunchDaemons", true},
		{"/Library/LaunchAgents", true},
	}

	home, err := os.UserHomeDir()
	if err == nil {
		dirs = append(dirs, struct {
			path     string
			isSystem bool
		}{filepath.Join(home, "Library/LaunchAgents"), false})
	}

	for _, d := range dirs {
		files, err := os.ReadDir(d.path)
		if err != nil {
			continue // Skip if directory doesn't exist or is unreadable
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".plist") && !f.IsDir() {
				items = append(items, StartupItem{
					Name:     strings.TrimSuffix(f.Name(), ".plist"),
					Path:     filepath.Join(d.path, f.Name()),
					IsSystem: d.isSystem,
				})
			}
		}
	}

	return items, nil
}

func DisableStartupItem(item StartupItem) error {
	script := fmt.Sprintf("launchctl unload -w \"%s\"", item.Path)
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}
