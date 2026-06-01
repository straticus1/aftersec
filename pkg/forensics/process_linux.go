//go:build linux

package forensics

import (
	"fmt"
	"os"
	"strings"
)

func GetProcessPath(pid int) (string, error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return target, nil
}

func GetOpenConnections(pid int) (int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
		if err == nil && strings.HasPrefix(link, "socket:") {
			count++
		}
	}
	return count, nil
}
