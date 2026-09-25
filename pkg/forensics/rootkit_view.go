package forensics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
)

// Threats: a rootkit finding is a disagreement between two views of one fact,
// or a kernel load that is not an Apple bundle. A view that cannot be read is
// an error, not a clean scan. A known module name does not clear a
// disagreement, and this package does not read kernel memory or time syscalls.

// RootkitFinding is one cross-view disagreement.
type RootkitFinding struct {
	DetectionType string
	Severity      string
	KEXTName      string
	KEXTPath      string
	ThreatScore   float64
	Evidence      map[string]interface{}
	Timestamp     time.Time
	Remediation   string
}

// RootkitDetector compares kernel and user views.
type RootkitDetector struct {
	mu sync.RWMutex
	db storage.Manager
}

var (
	rootkitDetector *RootkitDetector
	rootkitOnce     sync.Once
)

// InitRootkitDetector returns the process-wide detector.
func InitRootkitDetector(db storage.Manager) *RootkitDetector {
	rootkitOnce.Do(func() {
		rootkitDetector = &RootkitDetector{db: db}
	})
	return rootkitDetector
}

func (rd *RootkitDetector) record(findings []RootkitFinding) error {
	if rd == nil || rd.db == nil || len(findings) == 0 {
		return nil
	}
	rd.mu.Lock()
	defer rd.mu.Unlock()
	for _, finding := range findings {
		body, err := json.Marshal(struct {
			Type     string                 `json:"type"`
			Name     string                 `json:"name,omitempty"`
			Score    float64                `json:"score"`
			Evidence map[string]interface{} `json:"evidence,omitempty"`
		}{finding.DetectionType, finding.KEXTName, finding.ThreatScore, finding.Evidence})
		if err != nil {
			return err
		}
		if err = rd.db.LogTelemetryEvent("rootkit", finding.DetectionType, finding.Severity, string(body)); err != nil {
			return err
		}
	}
	return nil
}

// pidsOnlyIn returns pids present in primary and absent from secondary.
func pidsOnlyIn(primary, secondary map[int]struct{}) []int {
	var out []int
	for pid := range primary {
		if _, ok := secondary[pid]; ok {
			continue
		}
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}

// confirmedHidden keeps a pid only when the second pair of views still disagrees.
func confirmedHidden(firstKernel, firstListed, secondKernel, secondListed map[int]struct{}) []int {
	var out []int
	for _, pid := range pidsOnlyIn(firstKernel, firstListed) {
		if _, ok := secondKernel[pid]; !ok {
			continue
		}
		if _, ok := secondListed[pid]; ok {
			continue
		}
		out = append(out, pid)
	}
	return out
}

func parsePIDLines(text string) (map[int]struct{}, error) {
	pids := map[int]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil || pid <= 0 {
			return nil, fmt.Errorf("process list is unreadable")
		}
		pids[pid] = struct{}{}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("process list is empty")
	}
	return pids, nil
}

func nonAppleKexts(text string) ([]string, error) {
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("kext view is empty")
	}
	var names []string
	sawHeader := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return nil, fmt.Errorf("kext view is unreadable")
		}
		if fields[0] == "Index" {
			sawHeader = true
			continue
		}
		name := fields[5]
		if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, " \t/\\") {
			return nil, fmt.Errorf("kext view is unreadable")
		}
		if !strings.HasPrefix(name, "com.apple.") {
			names = append(names, name)
		}
	}
	if !sawHeader {
		return nil, fmt.Errorf("kext view is unreadable")
	}
	return names, nil
}

// moduleNeedsReview is true for a known rootkit name or a module missing from sysfs.
func moduleNeedsReview(knownName, inSysfs bool) bool {
	return knownName || !inSysfs
}

// suspiciousLibraryPath is true when a preload path is relative, temporary, or outside the OS library prefixes.
func suspiciousLibraryPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || strings.Contains(path, "\x00") || strings.Contains(path, "..") {
		return true
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == ':' || r == ' ' }) {
		if part == "" {
			continue
		}
		if !trustedLibrary(part) {
			return true
		}
	}
	return false
}

func trustedLibrary(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	for _, prefix := range []string{"/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/System/Library/", "/usr/local/lib/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
