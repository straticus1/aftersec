//go:build linux

package tuning

import (
	"aftersec/pkg/core"
	"errors"
	"os/exec"
)

func PurgeRAM() error {
	script := "sync && echo 3 > /proc/sys/vm/drop_caches"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func FlushDNS() error {
	if exec.Command("resolvectl", "flush-caches").Run() == nil {
		return nil
	}
	script := "systemctl restart nscd 2>/dev/null || systemctl restart systemd-resolved"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func ResetTCC() error {
	return errors.New("TCC is a macOS feature; not available on Linux")
}

func ClearSystemCaches() error {
	script := "sync && echo 3 > /proc/sys/vm/drop_caches"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func EmptyTrash() error {
	script := `rm -rf "$HOME/.local/share/Trash/files/"* "$HOME/.local/share/Trash/info/"*`
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func RebuildLaunchServices() error {
	return errors.New("Launch Services is a macOS feature; not available on Linux")
}

func GetBooleanDefault(_, _ string) bool {
	return false
}

func SetBooleanDefault(_, _ string, _ bool) error {
	return errors.New("macOS defaults system not available on Linux")
}

func ToggleDashboard(_ bool) error {
	return errors.New("Dashboard is a macOS feature; not available on Linux")
}

func ToggleCaptivePortal(_ bool) error {
	return errors.New("macOS captive portal control not available on Linux")
}

func ToggleAppStoreAutoUpdate(_ bool) error {
	return errors.New("App Store not available on Linux")
}

func SetUIAnimations(_ bool) error {
	return errors.New("macOS UI animation settings not available on Linux")
}

func DisableSpotlight(_ string) error {
	script := "systemctl stop updatedb.timer 2>/dev/null; systemctl disable updatedb.timer 2>/dev/null; true"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func EnableSpotlight(_ string) error {
	script := "systemctl enable --now updatedb.timer"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}
