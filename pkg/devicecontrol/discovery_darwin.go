//go:build darwin

package devicecontrol

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type DarwinIOKitSource struct {
	Interval time.Duration
}

func NewPlatformSource() Source { return DarwinIOKitSource{Interval: 2 * time.Second} }

func (s DarwinIOKitSource) Watch(ctx context.Context, emit func(Device) error) error {
	if s.Interval <= 0 {
		return fmt.Errorf("invalid IOKit discovery interval")
	}
	seen := make(map[DeviceID]struct{})
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		devices, err := discoverIOKitMedia(ctx)
		if err != nil {
			return err
		}
		for _, device := range devices {
			if _, ok := seen[device.ID]; ok {
				continue
			}
			seen[device.ID] = struct{}{}
			if err := emit(device); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ioreg is Apple's direct command-line view over the IOKit registry. Restrict
// parsing to removable IOMedia entries and their native BSD identity.
func discoverIOKitMedia(ctx context.Context) ([]Device, error) {
	output, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-r", "-c", "IOMedia", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("query IOKit removable media: %w", err)
	}
	var devices []Device
	var current Device
	removable := false
	flush := func() {
		if removable && current.ID != "" {
			current.Class = "mass-storage"
			devices = append(devices, current)
		}
		current, removable = Device{}, false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "+-o ") {
			flush()
			continue
		}
		key, value, ok := parseIORegProperty(line)
		if !ok {
			continue
		}
		switch key {
		case "BSD Name":
			current.ID = DeviceID("/dev/" + value)
		case "Removable":
			removable = value == "Yes"
		case "UUID":
			current.Serial = value
		case "Vendor Name":
			current.Vendor = value
		case "Product Name":
			current.Product = value
		}
	}
	flush()
	return devices, scanner.Err()
}

func parseIORegProperty(line string) (string, string, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.Trim(strings.TrimSpace(parts[0]), "\"")
	value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
	return key, value, true
}
