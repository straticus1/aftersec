//go:build !darwin && !linux

package devicecontrol

func NewPlatformSource() Source { return nil }
