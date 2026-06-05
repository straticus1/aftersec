# Patch Management — Detection & Remediation Design

## Goal

Surface unpatched CVEs on macOS and Linux endpoints as `core.Finding` entries, with remediation scripts pre-populated for a future one-click fix flow.

## Phasing

- **Phase 1 (now):** Detection — inventory packages, query CVEs, emit findings
- **Phase 2 (next):** Approval UI — user reviews + selects patches in GUI/CLI
- **Phase 3 (later):** Execution — daemon runs remediation scripts, records audit log

---

## Architecture

### New package: `pkg/patchmgr/`

```
pkg/patchmgr/
  patchmgr.go          # interface + shared types
  platform_darwin.go   # ForPlatform() returns [brew, softwareupdate]
  platform_linux.go    # ForPlatform() returns [apt | dnf | pacman]
  brew.go              # //go:build darwin
  softwareupdate.go    # //go:build darwin
  apt.go               # //go:build linux
  dnf.go               # //go:build linux
  pacman.go            # //go:build linux
  osv.go               # cross-platform OSV.dev CVE client
```

### Core interface

```go
type PackageManager interface {
    Name() string
    ListOutdated() ([]OutdatedPackage, error)
    RemediateCmd(pkg OutdatedPackage) string
}

type InstalledPackage struct {
    Name      string
    Version   string
    Source    string // "brew", "softwareupdate", "apt", "dnf", "pacman"
}

type OutdatedPackage struct {
    InstalledPackage
    LatestVersion string
    CVEs          []CVE
}

type CVE struct {
    ID          string  // "CVE-2024-12345"
    Score       float64 // CVSS v3
    Description string
}
```

---

## Package Manager Implementations

### macOS

| Manager | Command | Notes |
|---|---|---|
| Homebrew | `brew outdated --json=v2` | Structured JSON, clean name/version |
| softwareupdate | `softwareupdate -l` | macOS system + security updates |

### Linux

| Manager | Command | Distros |
|---|---|---|
| apt | `apt list --upgradable 2>/dev/null` | Debian, Ubuntu |
| dnf | `dnf check-update --quiet` | RHEL, Fedora, Rocky, Alma |
| pacman | `pacman -Qu` | Arch, Manjaro |

`ForPlatform()` auto-detects which managers are present via `exec.LookPath`.

---

## CVE Enrichment — OSV.dev

Single batch HTTP call, no API key required:

```
POST https://api.osv.dev/v1/querybatch
```

Ecosystem mapping:

| Source | OSV Ecosystem |
|---|---|
| brew | `Homebrew` |
| apt (Ubuntu) | `Ubuntu` |
| apt (Debian) | `Debian` |
| dnf | `AlmaLinux` / `Rocky Linux` |

All outdated packages sent in one request. CVSS scores parsed from `severity[].score`. Results enrich `OutdatedPackage.CVEs` in place.

---

## Integration with `pkg/scanners/vuln.go`

```go
func ScanVulnerabilities(addFinding func(core.Finding)) {
    for _, mgr := range patchmgr.ForPlatform() {
        outdated, err := mgr.ListOutdated()
        if err != nil { /* emit error finding */ continue }

        patchmgr.EnrichWithCVEs(outdated)

        // Individual finding per package with CVEs
        for _, pkg := range outdated {
            if len(pkg.CVEs) == 0 { continue }
            addFinding(core.Finding{
                Category:          "Patch Management",
                Name:              fmt.Sprintf("%s outdated (%s → %s)", pkg.Name, pkg.Version, pkg.LatestVersion),
                Severity:          cveSeverity(pkg.CVEs), // CVSS → core.Severity
                CurrentVal:        pkg.Version,
                ExpectedVal:       pkg.LatestVersion,
                LogContext:        formatCVEs(pkg.CVEs),
                Passed:            false,
                RemediationScript: mgr.RemediateCmd(pkg),
            })
        }

        // Rolled-up finding for outdated-but-no-CVE packages
        addOutdatedSummaryFinding(mgr, outdated, addFinding)
    }
}
```

CVSS → Severity mapping:

| CVSS | core.Severity |
|---|---|
| 9.0–10.0 | Critical |
| 7.0–8.9 | High |
| 4.0–6.9 | Med |
| 0.1–3.9 | Low |
| no CVE | Low (summary finding) |

---

## Remediation Path (Phase 2/3)

`RemediationScript` is already a field on `core.Finding`. Detection populates it; nothing else needs to change in the data model.

```
Detection now:   Finding.RemediationScript = "brew upgrade curl"
Phase 2:         GUI/CLI shows findings, user approves selected patches
Phase 3:         aftersecd executes script, records to patch_actions table
                 (finding_id, ran_at, exit_code, output, rolled_back)
```

Privilege elevation already exists:
- macOS: `core/remediate.go` uses osascript
- Linux: `core/remediate_linux.go` uses sudo

---

## Files to Create / Modify

| File | Action |
|---|---|
| `pkg/patchmgr/patchmgr.go` | Create — interface + types + EnrichWithCVEs + helpers |
| `pkg/patchmgr/platform_darwin.go` | Create — ForPlatform() for macOS |
| `pkg/patchmgr/platform_linux.go` | Create — ForPlatform() for Linux |
| `pkg/patchmgr/brew.go` | Create — Homebrew impl (darwin) |
| `pkg/patchmgr/softwareupdate.go` | Create — softwareupdate impl (darwin) |
| `pkg/patchmgr/apt.go` | Create — apt impl (linux) |
| `pkg/patchmgr/dnf.go` | Create — dnf impl (linux) |
| `pkg/patchmgr/pacman.go` | Create — pacman impl (linux) |
| `pkg/patchmgr/osv.go` | Create — OSV.dev batch CVE client |
| `pkg/scanners/vuln.go` | Modify — replace stub with patchmgr-backed impl |
