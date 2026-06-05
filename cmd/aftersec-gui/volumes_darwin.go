//go:build darwin

package main

import "os"

func detectAvailableVolumes() []VolumeInfo {
	var volumes []VolumeInfo

	volumes = append(volumes, VolumeInfo{
		Path:       "/",
		MountPoint: "/ (Root)",
		Filesystem: "apfs",
	})

	volumesDir := "/Volumes"
	if entries, err := os.ReadDir(volumesDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				volumes = append(volumes, VolumeInfo{
					Path:       volumesDir + "/" + entry.Name(),
					MountPoint: entry.Name(),
				})
			}
		}
	}

	if info, err := os.Stat("/System/Volumes/Data"); err == nil && info.IsDir() {
		volumes = append(volumes, VolumeInfo{
			Path:       "/System/Volumes/Data",
			MountPoint: "System Data",
			Filesystem: "apfs",
		})
	}

	return volumes
}
