package tuning

import (
	"aftersec/pkg/core"
	"fmt"
	"os/exec"
	"strings"
)

func PurgeRAM() error {
	script := "purge"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func FlushDNS() error {
	script := "dscacheutil -flushcache; killall -HUP mDNSResponder"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func ResetTCC() error {
	script := "tccutil reset All"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func ClearSystemCaches() error {
	script := "rm -rf /Library/Caches/* /System/Library/Caches/* ~/Library/Caches/*"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func EmptyTrash() error {
	script := "rm -rf ~/.Trash/* /Volumes/*/.Trashes/*"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func RebuildLaunchServices() error {
	script := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -kill -r -domain local -domain system -domain user"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func GetBooleanDefault(domain, key string) bool {
    // simplified read logic without privileged access since standard defaults read is safe
    out, _ := exec.Command("bash", "-c", fmt.Sprintf("defaults read %s %s || echo 0", domain, key)).CombinedOutput()
    return strings.Contains(strings.ToLower(string(out)), "1") || strings.Contains(strings.ToLower(string(out)), "true") || strings.Contains(strings.ToLower(string(out)), "yes")
}

func SetBooleanDefault(domain, key string, enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	script := fmt.Sprintf("defaults write %s %s -int %s", domain, key, val)
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func ToggleDashboard(enabled bool) error {
	err := SetBooleanDefault("com.apple.dashboard", "mcx-disabled", !enabled)
	if err == nil {
		script := "killall Dock"
		core.RegisterAllowedScript(script)
		_ = core.RunPrivileged(script)
	}
	return err
}

func ToggleCaptivePortal(enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	// Needs to be modified in /Library/Preferences/SystemConfiguration/com.apple.captive.control
	script := fmt.Sprintf("defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -int %s", val)
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func ToggleAppStoreAutoUpdate(enabled bool) error {
	val := "NO"
	if enabled {
		val = "YES"
	}
	script := fmt.Sprintf("defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool %s", val)
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func SetUIAnimations(fast bool) error {
	val := "0.2"
	if fast {
		val = "0.001"
	}
	script := fmt.Sprintf("defaults write NSGlobalDomain NSWindowResizeTime -float %s", val)
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func DisableSpotlight(path string) error {
    if path == "" {
        path = "/"
    }
    script := fmt.Sprintf("mdutil -i off %s", path)
    core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func EnableSpotlight(path string) error {
    if path == "" {
        path = "/"
    }
    script := fmt.Sprintf("mdutil -i on %s", path)
    core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}
