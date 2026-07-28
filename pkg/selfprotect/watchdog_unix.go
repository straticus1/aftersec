//go:build darwin || linux

package selfprotect

import "syscall"

func watchdogProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
