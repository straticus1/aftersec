package main

import (
	"aftersec/pkg/tuning"
)

// Setup routines
func PurgeRAM() error { return tuning.PurgeRAM() }
func FlushDNS() error { return tuning.FlushDNS() }
func EmptyTrash() error { return tuning.EmptyTrash() }
func ClearSystemCaches() error { return tuning.ClearSystemCaches() }
func ResetTCC() error { return tuning.ResetTCC() }
func RebuildLaunchServices() error { return tuning.RebuildLaunchServices() }

// System Toggles
func ToggleDashboard(enabled bool) error { return tuning.ToggleDashboard(enabled) }
func ToggleCaptivePortal(enabled bool) error { return tuning.ToggleCaptivePortal(enabled) }
func ToggleAppStoreAutoUpdate(enabled bool) error { return tuning.ToggleAppStoreAutoUpdate(enabled) }
func SetUIAnimations(fast bool) error { return tuning.SetUIAnimations(fast) }
func DisableSpotlight(path string) error { return tuning.DisableSpotlight(path) }
func EnableSpotlight(path string) error { return tuning.EnableSpotlight(path) }
func GetBooleanDefault(domain, key string) bool { return tuning.GetBooleanDefault(domain, key) }
func SetBooleanDefault(domain, key string, enabled bool) error { return tuning.SetBooleanDefault(domain, key, enabled) }

// Kernel Parameters
func GetSysctl(name string) (string, error) { return tuning.GetSysctl(name) }
func SetSysctl(name, val string) error { return tuning.SetSysctl(name, val) }
func GetRecommendedSysctls() []tuning.SysctlVariable { return tuning.GetRecommendedSysctls() }

// Startup Items
func GetStartupItems() ([]tuning.StartupItem, error) { return tuning.GetStartupItems() }
func DisableStartupItem(item tuning.StartupItem) error { return tuning.DisableStartupItem(item) }
