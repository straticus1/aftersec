//go:build linux

package devicecontrol

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type LinuxUdevSource struct{}

func NewPlatformSource() Source { return LinuxUdevSource{} }

func (LinuxUdevSource) Watch(ctx context.Context, emit func(Device) error) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		return fmt.Errorf("open udev netlink source: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}); err != nil {
		return fmt.Errorf("bind udev netlink source: %w", err)
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	buffer := make([]byte, 64<<10)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Poll(poll, 250)
		if err != nil {
			return fmt.Errorf("poll udev source: %w", err)
		}
		if n == 0 {
			continue
		}
		size, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return fmt.Errorf("read udev event: %w", err)
		}
		fields := parseUEvent(buffer[:size])
		if fields["ACTION"] != "add" || fields["SUBSYSTEM"] != "block" || fields["DEVNAME"] == "" {
			continue
		}
		device, ok := linuxBlockDevice(fields["DEVNAME"])
		if !ok {
			continue
		}
		if err := emit(device); err != nil {
			return err
		}
	}
}

func parseUEvent(data []byte) map[string]string {
	result := make(map[string]string)
	for _, field := range strings.Split(string(data), "\x00") {
		key, value, ok := strings.Cut(field, "=")
		if ok {
			result[key] = value
		}
	}
	return result
}

func linuxBlockDevice(name string) (Device, bool) {
	base := filepath.Base(name)
	sys := filepath.Join("/sys/class/block", base)
	removable, err := os.ReadFile(filepath.Join(sys, "removable"))
	if err != nil || strings.TrimSpace(string(removable)) != "1" {
		return Device{}, false
	}
	deviceRoot := filepath.Join(sys, "device")
	return Device{
		ID:      DeviceID(filepath.Join("/dev", base)),
		Class:   "mass-storage",
		Vendor:  readSysAttribute(deviceRoot, "vendor"),
		Product: readSysAttribute(deviceRoot, "model"),
		Serial:  readSysAttribute(deviceRoot, "serial"),
	}, true
}

func readSysAttribute(root, name string) string {
	data, _ := os.ReadFile(filepath.Join(root, name))
	return strings.TrimSpace(string(data))
}
