package main

// VolumeInfo describes a mounted filesystem available for scanning.
type VolumeInfo struct {
	Path       string
	MountPoint string
	Filesystem string
}
