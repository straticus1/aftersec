# Patch Management Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add CVE-aware patch detection for macOS (Homebrew + softwareupdate) and Linux (apt/dnf/pacman) that emits `core.Finding` entries with pre-populated `RemediationScript` fields.

**Architecture:** New `pkg/patchmgr/` package with a `PackageManager` interface and per-manager impls. A cross-platform OSV.dev client enriches packages with CVE data. `pkg/scanners/vuln.go` is updated to use `patchmgr.ForPlatform()` instead of a raw `brew outdated` shell call.

**Tech Stack:** Go stdlib (`net/http`, `os/exec`, `encoding/json`), OSV.dev batch API (free, no key), build tags for platform isolation (`//go:build darwin`, `//go:build linux`).

**Worktree:** `.worktrees/feature-patch-management` on branch `feature/patch-management`

---

## Task 1: Core types and interface

**Files:**
- Create: `pkg/patchmgr/patchmgr.go`
- Create: `pkg/patchmgr/patchmgr_test.go`

**Step 1: Create `pkg/patchmgr/patchmgr.go`**

```go
package patchmgr

import "aftersec/pkg/core"

// PackageManager discovers outdated packages and generates remediation commands.
type PackageManager interface {
	Name() string
	ListOutdated() ([]OutdatedPackage, error)
	RemediateCmd(pkg OutdatedPackage) string
}

type InstalledPackage struct {
	Name    string
	Version string
	Source  string // "brew", "softwareupdate", "apt", "dnf", "pacman"
}

type OutdatedPackage struct {
	InstalledPackage
	LatestVersion string
	CVEs          []CVE
}

type CVE struct {
	ID          string
	Score       float64 // CVSS v3 base score; 0 if unknown
	Description string
}

// CVESeverity maps the highest CVE score in a package to a core.Severity.
func CVESeverity(cves []CVE) core.Severity {
	var max float64
	for _, c := range cves {
		if c.Score > max {
			max = c.Score
		}
	}
	switch {
	case max >= 9.0:
		return core.Critical
	case max >= 7.0:
		return core.High
	case max >= 4.0:
		return core.Med
	default:
		return core.Low
	}
}

// FormatCVEs returns a compact string listing CVE IDs and scores.
func FormatCVEs(cves []CVE) string {
	if len(cves) == 0 {
		return ""
	}
	out := ""
	for i, c := range cves {
		if i > 0 {
			out += ", "
		}
		if c.Score > 0 {
			out += fmt.Sprintf("%s (%.1f)", c.ID, c.Score)
		} else {
			out += c.ID
		}
	}
	return out
}
```

Add `"fmt"` to imports.

**Step 2: Write `pkg/patchmgr/patchmgr_test.go`**

```go
package patchmgr

import (
	"aftersec/pkg/core"
	"testing"
)

func TestCVESeverity(t *testing.T) {
	cases := []struct {
		scores []float64
		want   core.Severity
	}{
		{[]float64{9.8}, core.Critical},
		{[]float64{7.5}, core.High},
		{[]float64{9.8, 4.0}, core.Critical}, // highest wins
		{[]float64{5.5}, core.Med},
		{[]float64{2.0}, core.Low},
		{[]float64{}, core.Low}, // no CVEs → Low
		{[]float64{0}, core.Low},
	}
	for _, tc := range cases {
		cves := make([]CVE, len(tc.scores))
		for i, s := range tc.scores {
			cves[i] = CVE{Score: s}
		}
		got := CVESeverity(cves)
		if got != tc.want {
			t.Errorf("scores=%v: got %s, want %s", tc.scores, got, tc.want)
		}
	}
}

func TestFormatCVEs(t *testing.T) {
	cves := []CVE{
		{ID: "CVE-2024-1234", Score: 9.8},
		{ID: "CVE-2024-5678", Score: 0},
	}
	got := FormatCVEs(cves)
	if got != "CVE-2024-1234 (9.8), CVE-2024-5678" {
		t.Errorf("unexpected: %q", got)
	}
	if FormatCVEs(nil) != "" {
		t.Error("expected empty string for nil CVEs")
	}
}
```

**Step 3: Run test — verify it passes**

```bash
cd .worktrees/feature-patch-management
go test ./pkg/patchmgr/... -v
```

Expected: PASS (2 tests)

**Step 4: Commit**

```bash
git add pkg/patchmgr/patchmgr.go pkg/patchmgr/patchmgr_test.go
git commit -m "feat(patchmgr): add core types, PackageManager interface, CVE helpers"
```

---

## Task 2: Homebrew implementation (macOS)

**Files:**
- Create: `pkg/patchmgr/brew.go` (`//go:build darwin`)
- Create: `pkg/patchmgr/brew_test.go` (`//go:build darwin`)

**Step 1: Create `pkg/patchmgr/brew.go`**

```go
//go:build darwin

package patchmgr

import (
	"encoding/json"
	"os/exec"
)

type BrewManager struct {
	run func() ([]byte, error)
}

func NewBrewManager() *BrewManager {
	return &BrewManager{
		run: func() ([]byte, error) {
			return exec.Command("brew", "outdated", "--json=v2").CombinedOutput()
		},
	}
}

func (b *BrewManager) Name() string { return "brew" }

func (b *BrewManager) RemediateCmd(pkg OutdatedPackage) string {
	return "brew upgrade " + pkg.Name
}

func (b *BrewManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := b.run()
	if err != nil {
		return nil, err
	}
	return parseBrewJSON(data)
}

type brewJSON struct {
	Formulae []struct {
		Name               string   `json:"name"`
		InstalledVersions  []string `json:"installed_versions"`
		CurrentVersion     string   `json:"current_version"`
	} `json:"formulae"`
}

func parseBrewJSON(data []byte) ([]OutdatedPackage, error) {
	var b brewJSON
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	pkgs := make([]OutdatedPackage, 0, len(b.Formulae))
	for _, f := range b.Formulae {
		installed := ""
		if len(f.InstalledVersions) > 0 {
			installed = f.InstalledVersions[0]
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:    f.Name,
				Version: installed,
				Source:  "brew",
			},
			LatestVersion: f.CurrentVersion,
		})
	}
	return pkgs, nil
}
```

**Step 2: Write `pkg/patchmgr/brew_test.go`**

```go
//go:build darwin

package patchmgr

import (
	"errors"
	"testing"
)

var brewFixture = []byte(`{
  "formulae": [
    {"name":"curl","installed_versions":["8.1.0"],"current_version":"8.6.0"},
    {"name":"openssl@3","installed_versions":["3.2.0"],"current_version":"3.3.1"}
  ],
  "casks": []
}`)

func TestParseBrewJSON(t *testing.T) {
	pkgs, err := parseBrewJSON(brewFixture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "8.1.0" || pkgs[0].LatestVersion != "8.6.0" {
		t.Errorf("unexpected pkg[0]: %+v", pkgs[0])
	}
	if pkgs[0].Source != "brew" {
		t.Errorf("expected source 'brew', got %q", pkgs[0].Source)
	}
}

func TestBrewManager_ListOutdated_ParseError(t *testing.T) {
	mgr := &BrewManager{run: func() ([]byte, error) { return []byte("not json"), nil }}
	_, err := mgr.ListOutdated()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBrewManager_ListOutdated_RunError(t *testing.T) {
	mgr := &BrewManager{run: func() ([]byte, error) { return nil, errors.New("brew not found") }}
	_, err := mgr.ListOutdated()
	if err == nil {
		t.Error("expected error when run fails")
	}
}

func TestBrewManager_RemediateCmd(t *testing.T) {
	mgr := NewBrewManager()
	pkg := OutdatedPackage{InstalledPackage: InstalledPackage{Name: "curl"}}
	if got := mgr.RemediateCmd(pkg); got != "brew upgrade curl" {
		t.Errorf("unexpected: %q", got)
	}
}
```

**Step 3: Run tests**

```bash
go test ./pkg/patchmgr/... -v
```

Expected: PASS (4 brew tests + 2 patchmgr tests)

**Step 4: Commit**

```bash
git add pkg/patchmgr/brew.go pkg/patchmgr/brew_test.go
git commit -m "feat(patchmgr): add Homebrew manager with JSON parsing"
```

---

## Task 3: SoftwareUpdate implementation (macOS)

**Files:**
- Create: `pkg/patchmgr/softwareupdate.go` (`//go:build darwin`)
- Create: `pkg/patchmgr/softwareupdate_test.go` (`//go:build darwin`)

**Step 1: Create `pkg/patchmgr/softwareupdate.go`**

```go
//go:build darwin

package patchmgr

import (
	"os/exec"
	"regexp"
	"strings"
)

type SoftwareUpdateManager struct {
	run func() ([]byte, error)
}

func NewSoftwareUpdateManager() *SoftwareUpdateManager {
	return &SoftwareUpdateManager{
		run: func() ([]byte, error) {
			return exec.Command("softwareupdate", "-l").CombinedOutput()
		},
	}
}

func (s *SoftwareUpdateManager) Name() string { return "softwareupdate" }

func (s *SoftwareUpdateManager) RemediateCmd(pkg OutdatedPackage) string {
	return "softwareupdate --install " + pkg.Name
}

func (s *SoftwareUpdateManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := s.run()
	if err != nil {
		return nil, err
	}
	return parseSoftwareUpdateOutput(string(data)), nil
}

// labelRe matches lines like: * Label: Safari-17.4.1
var labelRe = regexp.MustCompile(`\*\s+Label:\s+(.+)`)

// titleVersionRe matches lines like:	Title: Safari, Version: 17.4.1, ...
var titleVersionRe = regexp.MustCompile(`Title:\s+([^,]+),\s+Version:\s+([^,]+)`)

func parseSoftwareUpdateOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	lines := strings.Split(output, "\n")
	var label string
	for _, line := range lines {
		if m := labelRe.FindStringSubmatch(line); m != nil {
			label = strings.TrimSpace(m[1])
			continue
		}
		if label != "" {
			if m := titleVersionRe.FindStringSubmatch(line); m != nil {
				pkgs = append(pkgs, OutdatedPackage{
					InstalledPackage: InstalledPackage{
						Name:   label,
						Source: "softwareupdate",
					},
					LatestVersion: strings.TrimSpace(m[2]),
				})
				label = ""
			}
		}
	}
	return pkgs
}
```

**Step 2: Write `pkg/patchmgr/softwareupdate_test.go`**

```go
//go:build darwin

package patchmgr

import "testing"

var suFixture = `
Software Update found the following new or updated software:
* Label: macOS Sequoia 15.4.1-24E263
	Title: macOS Sequoia 15.4.1, Version: 15.4.1, Size: 2145360KiB, Recommended: YES,
* Label: Safari-18.4.1
	Title: Safari, Version: 18.4.1, Size: 76180KiB, Recommended: YES,
`

func TestParseSoftwareUpdateOutput(t *testing.T) {
	pkgs := parseSoftwareUpdateOutput(suFixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "macOS Sequoia 15.4.1-24E263" {
		t.Errorf("unexpected name: %q", pkgs[0].Name)
	}
	if pkgs[0].LatestVersion != "15.4.1" {
		t.Errorf("unexpected version: %q", pkgs[0].LatestVersion)
	}
	if pkgs[1].Name != "Safari-18.4.1" {
		t.Errorf("unexpected name: %q", pkgs[1].Name)
	}
	if pkgs[0].Source != "softwareupdate" {
		t.Errorf("expected source 'softwareupdate', got %q", pkgs[0].Source)
	}
}

func TestParseSoftwareUpdateOutput_NoUpdates(t *testing.T) {
	pkgs := parseSoftwareUpdateOutput("Software Update found no new software.")
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}
```

**Step 3: Run tests**

```bash
go test ./pkg/patchmgr/... -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add pkg/patchmgr/softwareupdate.go pkg/patchmgr/softwareupdate_test.go
git commit -m "feat(patchmgr): add softwareupdate manager for macOS system patches"
```

---

## Task 4: Linux implementations (apt, dnf, pacman)

**Files:**
- Create: `pkg/patchmgr/apt.go` (`//go:build linux`)
- Create: `pkg/patchmgr/dnf.go` (`//go:build linux`)
- Create: `pkg/patchmgr/pacman.go` (`//go:build linux`)
- Create: `pkg/patchmgr/linux_test.go` (`//go:build linux`)

**Step 1: Create `pkg/patchmgr/apt.go`**

```go
//go:build linux

package patchmgr

import (
	"os/exec"
	"regexp"
	"strings"
)

type AptManager struct {
	run func() ([]byte, error)
}

func NewAptManager() *AptManager {
	return &AptManager{
		run: func() ([]byte, error) {
			return exec.Command("apt", "list", "--upgradable").CombinedOutput()
		},
	}
}

func (a *AptManager) Name() string { return "apt" }

func (a *AptManager) RemediateCmd(pkg OutdatedPackage) string {
	return "apt-get install --only-upgrade -y " + pkg.Name
}

func (a *AptManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := a.run()
	if err != nil {
		return nil, err
	}
	return parseAptOutput(string(data)), nil
}

// aptLineRe matches: curl/focal-security 7.68.0-1 amd64 [upgradable from: 7.68.0-0]
var aptLineRe = regexp.MustCompile(`^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]`)

func parseAptOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	for _, line := range strings.Split(output, "\n") {
		m := aptLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:    m[1],
				Version: m[3],
				Source:  "apt",
			},
			LatestVersion: m[2],
		})
	}
	return pkgs
}
```

**Step 2: Create `pkg/patchmgr/dnf.go`**

```go
//go:build linux

package patchmgr

import (
	"os/exec"
	"strings"
)

type DnfManager struct {
	run func() ([]byte, error)
}

func NewDnfManager() *DnfManager {
	return &DnfManager{
		run: func() ([]byte, error) {
			return exec.Command("dnf", "check-update", "--quiet").CombinedOutput()
		},
	}
}

func (d *DnfManager) Name() string { return "dnf" }

func (d *DnfManager) RemediateCmd(pkg OutdatedPackage) string {
	return "dnf upgrade -y " + pkg.Name
}

func (d *DnfManager) ListOutdated() ([]OutdatedPackage, error) {
	data, _ := d.run() // dnf check-update exits 100 when updates exist; ignore error
	return parseDnfOutput(string(data)), nil
}

// dnf check-update output: "curl.x86_64    7.76.1-31.el9    baseos"
func parseDnfOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Skip header lines and blank lines
		name := fields[0]
		if strings.HasPrefix(name, "Last") || strings.HasPrefix(name, "Obsoleting") {
			continue
		}
		// Strip arch suffix: curl.x86_64 → curl
		if idx := strings.LastIndex(name, "."); idx > 0 {
			name = name[:idx]
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:   name,
				Source: "dnf",
			},
			LatestVersion: fields[1],
		})
	}
	return pkgs
}
```

**Step 3: Create `pkg/patchmgr/pacman.go`**

```go
//go:build linux

package patchmgr

import (
	"os/exec"
	"strings"
)

type PacmanManager struct {
	run func() ([]byte, error)
}

func NewPacmanManager() *PacmanManager {
	return &PacmanManager{
		run: func() ([]byte, error) {
			return exec.Command("pacman", "-Qu").CombinedOutput()
		},
	}
}

func (p *PacmanManager) Name() string { return "pacman" }

func (p *PacmanManager) RemediateCmd(pkg OutdatedPackage) string {
	return "pacman -S --noconfirm " + pkg.Name
}

func (p *PacmanManager) ListOutdated() ([]OutdatedPackage, error) {
	data, err := p.run()
	if err != nil {
		return nil, err
	}
	return parsePacmanOutput(string(data)), nil
}

// pacman -Qu output: "curl 8.1.2-1 -> 8.6.0-1"
func parsePacmanOutput(output string) []OutdatedPackage {
	var pkgs []OutdatedPackage
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pkgs = append(pkgs, OutdatedPackage{
			InstalledPackage: InstalledPackage{
				Name:    fields[0],
				Version: fields[1],
				Source:  "pacman",
			},
			LatestVersion: fields[3],
		})
	}
	return pkgs
}
```

**Step 4: Create `pkg/patchmgr/linux_test.go`**

```go
//go:build linux

package patchmgr

import "testing"

func TestParseAptOutput(t *testing.T) {
	fixture := `Listing...
curl/focal-security 7.68.0-1ubuntu2.22 amd64 [upgradable from: 7.68.0-1ubuntu2.21]
openssl/focal-security 1.1.1f-1ubuntu2.22 amd64 [upgradable from: 1.1.1f-1ubuntu2.21]
`
	pkgs := parseAptOutput(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "7.68.0-1ubuntu2.21" {
		t.Errorf("unexpected pkg[0]: %+v", pkgs[0])
	}
	if pkgs[0].LatestVersion != "7.68.0-1ubuntu2.22" {
		t.Errorf("unexpected latest: %q", pkgs[0].LatestVersion)
	}
}

func TestParseDnfOutput(t *testing.T) {
	fixture := `
curl.x86_64    7.76.1-31.el9    baseos
openssl.x86_64 3.0.7-28.el9     baseos
`
	pkgs := parseDnfOutput(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].LatestVersion != "7.76.1-31.el9" {
		t.Errorf("unexpected: %+v", pkgs[0])
	}
}

func TestParsePacmanOutput(t *testing.T) {
	fixture := `curl 8.1.2-1 -> 8.6.0-1
openssl 3.1.0-1 -> 3.3.1-1
`
	pkgs := parsePacmanOutput(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "8.1.2-1" || pkgs[0].LatestVersion != "8.6.0-1" {
		t.Errorf("unexpected: %+v", pkgs[0])
	}
}
```

**Step 5: Run tests (on Linux; skip on macOS — build tags exclude linux files)**

```bash
go test ./pkg/patchmgr/... -v
```

On macOS: linux tests are excluded by build tags — PASS for darwin tests only.

**Step 6: Commit**

```bash
git add pkg/patchmgr/apt.go pkg/patchmgr/dnf.go pkg/patchmgr/pacman.go pkg/patchmgr/linux_test.go
git commit -m "feat(patchmgr): add apt, dnf, pacman managers for Linux"
```

---

## Task 5: OSV.dev CVE client

**Files:**
- Create: `pkg/patchmgr/osv.go`
- Create: `pkg/patchmgr/osv_test.go`

**Step 1: Create `pkg/patchmgr/osv.go`**

```go
package patchmgr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// ecosystemFor maps a package source to the OSV ecosystem name.
func ecosystemFor(source string) string {
	switch source {
	case "brew":
		return "Homebrew"
	case "apt":
		return "Debian" // caller can override for Ubuntu
	case "dnf":
		return "AlmaLinux"
	case "pacman":
		return "Arch Linux"
	default:
		return ""
	}
}

type osvRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPkg `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// EnrichWithCVEs queries OSV.dev for all packages in a single batch request
// and populates CVEs in-place. Packages with no known ecosystem are skipped.
func EnrichWithCVEs(pkgs []OutdatedPackage) {
	queries := make([]osvQuery, 0, len(pkgs))
	indices := make([]int, 0, len(pkgs))
	for i, p := range pkgs {
		eco := ecosystemFor(p.Source)
		if eco == "" {
			continue
		}
		queries = append(queries, osvQuery{
			Package: osvPkg{Name: p.Name, Ecosystem: eco},
			Version: p.Version,
		})
		indices = append(indices, i)
	}
	if len(queries) == 0 {
		return
	}

	body, err := json.Marshal(osvRequest{Queries: queries})
	if err != nil {
		return
	}

	resp, err := http.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return
	}

	for ri, result := range osvResp.Results {
		if ri >= len(indices) {
			break
		}
		pkgIdx := indices[ri]
		for _, v := range result.Vulns {
			cveID := cveIDFrom(v)
			score := cvssScore(v)
			pkgs[pkgIdx].CVEs = append(pkgs[pkgIdx].CVEs, CVE{
				ID:          cveID,
				Score:       score,
				Description: v.Summary,
			})
		}
	}
}

// cveIDFrom extracts a CVE ID from an OSV vuln, preferring aliases.
func cveIDFrom(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// cvssScore extracts the CVSS v3 base score from the severity field.
// OSV returns the full vector string (e.g. "CVSS:3.1/AV:N/AC:L/...").
// We extract it from CVSS:3.x/.../<base_score> or fall back to 0.
func cvssScore(v osvVuln) float64 {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			return parseCVSSVector(s.Score)
		}
	}
	return 0
}

// parseCVSSVector returns the base score encoded in a CVSS v3 vector string
// by using the standard metric weights. Returns 0 on parse error.
// This is a simplified lookup covering the most common vectors.
func parseCVSSVector(vector string) float64 {
	// CVSS:3.x/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
	// Rather than implement the full formula, map the 4 impact severity
	// combos to rough scores that align with NVD Critical/High/Med/Low.
	upper := strings.ToUpper(vector)
	cHigh := strings.Contains(upper, "/C:H")
	iHigh := strings.Contains(upper, "/I:H")
	aHigh := strings.Contains(upper, "/A:H")
	cMed := strings.Contains(upper, "/C:L")
	iMed := strings.Contains(upper, "/I:L")
	aMed := strings.Contains(upper, "/A:L")
	network := strings.Contains(upper, "AV:N")

	highCount := 0
	if cHigh { highCount++ }
	if iHigh { highCount++ }
	if aHigh { highCount++ }
	medCount := 0
	if cMed { medCount++ }
	if iMed { medCount++ }
	if aMed { medCount++ }

	switch {
	case highCount >= 3 && network:
		return 9.8
	case highCount >= 2 && network:
		return 8.8
	case highCount >= 1 && network:
		return 7.5
	case highCount >= 1:
		return 7.0
	case medCount >= 2:
		return 5.5
	case medCount >= 1:
		return 4.3
	default:
		return 3.1
	}
}

var _ = fmt.Sprintf // suppress unused import if needed
```

**Step 2: Create `pkg/patchmgr/osv_test.go`**

```go
package patchmgr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrichWithCVEs(t *testing.T) {
	// Fake OSV response: first package has a CVE, second has none
	fakeResp := osvResponse{
		Results: []struct {
			Vulns []osvVuln `json:"vulns"`
		}{
			{Vulns: []osvVuln{
				{
					ID:      "GHSA-abcd-1234-efgh",
					Aliases: []string{"CVE-2024-12345"},
					Summary: "Remote code execution",
					Severity: []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					}{
						{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
					},
				},
			}},
			{Vulns: nil},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fakeResp)
	}))
	defer srv.Close()

	// Patch the URL for testing
	orig := osvBatchURL
	// We need to make osvBatchURL patchable — see note below
	_ = orig

	pkgs := []OutdatedPackage{
		{InstalledPackage: InstalledPackage{Name: "curl", Version: "8.1.0", Source: "brew"}},
		{InstalledPackage: InstalledPackage{Name: "openssl", Version: "3.2.0", Source: "brew"}},
	}

	enrichWithCVEsURL(pkgs, srv.URL)

	if len(pkgs[0].CVEs) != 1 {
		t.Fatalf("expected 1 CVE for curl, got %d", len(pkgs[0].CVEs))
	}
	if pkgs[0].CVEs[0].ID != "CVE-2024-12345" {
		t.Errorf("unexpected CVE ID: %q", pkgs[0].CVEs[0].ID)
	}
	if pkgs[0].CVEs[0].Score < 9.0 {
		t.Errorf("expected critical score, got %.1f", pkgs[0].CVEs[0].Score)
	}
	if len(pkgs[1].CVEs) != 0 {
		t.Errorf("expected 0 CVEs for openssl, got %d", len(pkgs[1].CVEs))
	}
}

func TestParseCVSSVector(t *testing.T) {
	cases := []struct {
		vector string
		minScore float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.0},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 3.0},
	}
	for _, tc := range cases {
		got := parseCVSSVector(tc.vector)
		if got < tc.minScore {
			t.Errorf("vector=%q: got %.1f, want >= %.1f", tc.vector, got, tc.minScore)
		}
	}
}

func TestCVEIDFrom_PrefersAlias(t *testing.T) {
	v := osvVuln{ID: "GHSA-xxxx", Aliases: []string{"PYSEC-2024-1", "CVE-2024-9999"}}
	if got := cveIDFrom(v); got != "CVE-2024-9999" {
		t.Errorf("expected CVE alias, got %q", got)
	}
}

func TestCVEIDFrom_FallsBackToID(t *testing.T) {
	v := osvVuln{ID: "GHSA-xxxx", Aliases: []string{"PYSEC-2024-1"}}
	if got := cveIDFrom(v); got != "GHSA-xxxx" {
		t.Errorf("expected GHSA ID, got %q", got)
	}
}
```

> **Note:** The test uses `enrichWithCVEsURL(pkgs, url)` — a test-friendly variant of `EnrichWithCVEs` that accepts a custom URL. Add this to `osv.go`:
>
> ```go
> func enrichWithCVEsURL(pkgs []OutdatedPackage, url string) {
>     // same as EnrichWithCVEs but with url parameter
>     // extract the shared logic into an internal helper
> }
> ```
> Refactor `EnrichWithCVEs` to call `enrichWithCVEsURL(pkgs, osvBatchURL)`.

**Step 3: Run tests**

```bash
go test ./pkg/patchmgr/... -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add pkg/patchmgr/osv.go pkg/patchmgr/osv_test.go
git commit -m "feat(patchmgr): add OSV.dev batch CVE client with CVSS score parsing"
```

---

## Task 6: Platform selectors

**Files:**
- Create: `pkg/patchmgr/platform_darwin.go` (`//go:build darwin`)
- Create: `pkg/patchmgr/platform_linux.go` (`//go:build linux`)

**Step 1: Create `pkg/patchmgr/platform_darwin.go`**

```go
//go:build darwin

package patchmgr

import "os/exec"

// ForPlatform returns all available package managers on macOS.
func ForPlatform() []PackageManager {
	var mgrs []PackageManager
	if _, err := exec.LookPath("brew"); err == nil {
		mgrs = append(mgrs, NewBrewManager())
	}
	mgrs = append(mgrs, NewSoftwareUpdateManager())
	return mgrs
}
```

**Step 2: Create `pkg/patchmgr/platform_linux.go`**

```go
//go:build linux

package patchmgr

import "os/exec"

// ForPlatform returns all available package managers on Linux.
func ForPlatform() []PackageManager {
	var mgrs []PackageManager
	if _, err := exec.LookPath("apt"); err == nil {
		mgrs = append(mgrs, NewAptManager())
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		mgrs = append(mgrs, NewDnfManager())
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		mgrs = append(mgrs, NewPacmanManager())
	}
	return mgrs
}
```

**Step 3: Verify it compiles**

```bash
go build ./pkg/patchmgr/...
```

Expected: no errors

**Step 4: Commit**

```bash
git add pkg/patchmgr/platform_darwin.go pkg/patchmgr/platform_linux.go
git commit -m "feat(patchmgr): add ForPlatform() selectors for darwin and linux"
```

---

## Task 7: Wire into `pkg/scanners/vuln.go`

**Files:**
- Modify: `pkg/scanners/vuln.go`
- Create: `pkg/scanners/vuln_test.go`

**Step 1: Replace `pkg/scanners/vuln.go`**

```go
package scanners

import (
	"aftersec/pkg/core"
	"aftersec/pkg/patchmgr"
	"fmt"
)

func ScanVulnerabilities(addFinding func(core.Finding)) {
	for _, mgr := range patchmgr.ForPlatform() {
		outdated, err := mgr.ListOutdated()
		if err != nil {
			addFinding(core.Finding{
				Category:    "Patch Management",
				Name:        fmt.Sprintf("%s: scan failed", mgr.Name()),
				Description: "Could not retrieve package list.",
				Severity:    core.Low,
				CurrentVal:  err.Error(),
				ExpectedVal: "no error",
				Passed:      false,
			})
			continue
		}

		patchmgr.EnrichWithCVEs(outdated)

		noUpdate := true
		var noCVEOutdated []patchmgr.OutdatedPackage
		for _, pkg := range outdated {
			if len(pkg.CVEs) == 0 {
				noCVEOutdated = append(noCVEOutdated, pkg)
				continue
			}
			noUpdate = false
			addFinding(core.Finding{
				Category:          "Patch Management",
				Name:              fmt.Sprintf("[%s] %s outdated", mgr.Name(), pkg.Name),
				Description:       fmt.Sprintf("Installed: %s, Latest: %s", pkg.Version, pkg.LatestVersion),
				Severity:          patchmgr.CVESeverity(pkg.CVEs),
				CurrentVal:        pkg.Version,
				ExpectedVal:       pkg.LatestVersion,
				LogContext:        patchmgr.FormatCVEs(pkg.CVEs),
				Passed:            false,
				RemediationScript: mgr.RemediateCmd(pkg),
			})
		}

		// Rolled-up finding for outdated packages without known CVEs
		if len(noCVEOutdated) > 0 {
			noUpdate = false
			addFinding(core.Finding{
				Category:    "Patch Management",
				Name:        fmt.Sprintf("[%s] %d outdated package(s), no known CVEs", mgr.Name(), len(noCVEOutdated)),
				Severity:    core.Low,
				CurrentVal:  fmt.Sprintf("%d outdated", len(noCVEOutdated)),
				ExpectedVal: "0 outdated",
				Passed:      false,
			})
		}

		if noUpdate && len(outdated) == 0 {
			addFinding(core.Finding{
				Category:    "Patch Management",
				Name:        fmt.Sprintf("[%s] all packages up to date", mgr.Name()),
				Severity:    core.Low,
				CurrentVal:  "up to date",
				ExpectedVal: "up to date",
				Passed:      true,
			})
		}
	}
}
```

**Step 2: Create `pkg/scanners/vuln_test.go`**

```go
package scanners

import (
	"aftersec/pkg/core"
	"testing"
)

func TestScanVulnerabilities_NoManagers(t *testing.T) {
	// On macOS dev machine this will call real ForPlatform().
	// We just verify it doesn't panic and returns findings.
	var findings []core.Finding
	ScanVulnerabilities(func(f core.Finding) {
		findings = append(findings, f)
	})
	// At minimum expect at least one finding (up to date or outdated)
	if len(findings) == 0 {
		t.Error("expected at least one finding from ScanVulnerabilities")
	}
	for _, f := range findings {
		if f.Category != "Patch Management" {
			t.Errorf("unexpected category: %q", f.Category)
		}
		if f.Name == "" {
			t.Error("finding has empty name")
		}
	}
}
```

**Step 3: Run all tests**

```bash
go test ./pkg/patchmgr/... ./pkg/scanners/... -v
```

Expected: PASS

**Step 4: Run full build to confirm no broken imports**

```bash
go build ./...
```

Expected: no errors

**Step 5: Commit**

```bash
git add pkg/scanners/vuln.go pkg/scanners/vuln_test.go
git commit -m "feat(scanners): wire patchmgr into ScanVulnerabilities with CVE-per-finding output"
```

---

## Done

After all tasks complete, run the full test suite one final time:

```bash
go test ./... 2>&1 | grep -E "^(ok|FAIL|\?)"
```

Expected: same pass/fail profile as baseline (only `tests/integration` FAIL due to pre-existing missing server — unrelated to this feature).

Then use `superpowers:finishing-a-development-branch` to merge and clean up the worktree.
