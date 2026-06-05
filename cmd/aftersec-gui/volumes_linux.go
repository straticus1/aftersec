//go:build linux

package main

import (
	"bufio"
	"os"
	"strings"
)

func detectAvailableVolumes() []VolumeInfo {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return []VolumeInfo{{Path: "/", MountPoint: "/ (Root)", Filesystem: "unknown"}}
	}
	defer f.Close()

	pseudoFS := map[string]bool{
		"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
		"tmpfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"securityfs": true, "debugfs": true, "hugetlbfs": true, "mqueue": true,
		"fusectl": true, "bpf": true, "tracefs": true, "configfs": true,
		"ramfs": true, "efivarfs": true, "autofs": true,
	}

	seen := make(map[string]bool)
	var volumes []VolumeInfo

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mountPoint, fsType := fields[1], fields[2]
		if pseudoFS[fsType] || seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true

		label := mountPoint
		if mountPoint == "/" {
			label = "/ (Root)"
		}
		volumes = append(volumes, VolumeInfo{
			Path:       mountPoint,
			MountPoint: label,
			Filesystem: fsType,
		})
	}

	if len(volumes) == 0 {
		volumes = append(volumes, VolumeInfo{Path: "/", MountPoint: "/ (Root)", Filesystem: "unknown"})
	}
	return volumes
}
