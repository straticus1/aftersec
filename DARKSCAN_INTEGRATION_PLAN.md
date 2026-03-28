# DarkScan Integration Plan for AfterSec

**Status**: 43% Complete (6 of 14 features)
**Updated**: 2026-03-28
**Target Completion**: 8 new features across CLI + GUI

---

## Executive Summary

AfterSec currently integrates **43% of DarkScan's capabilities**. This plan details how to add the remaining **8 missing features** across three layers:

1. **CLI Commands** (Priority 1) - ~1,700 LOC
2. **Fyne Desktop GUI** (Priority 2) - ~1,200 LOC
3. **Next.js Web Dashboard** (Priority 3) - ~2,000 LOC

**Total Estimated Effort**: ~4,900 LOC across 15-20 new files

---

## Phase 1: CLI Implementation (Priority: HIGH)

### 1.1 Privacy Scanner Command

**File**: `cmd/aftersec/cmd/darkscan_privacy.go` (~400 LOC)

**DarkScan Methods to Wire**:
```go
ScanBrowserPrivacy(ctx, browsers []string) ([]PrivacyFinding, error)
ScanApplicationTelemetry(ctx, appPath string) ([]TelemetryFinding, error)
ListPrivacyFindings(ctx, filters PrivacyFilters) ([]PrivacyFinding, error)
RemoveTrackers(ctx, browser string, trackerIDs []string) error
ClearBrowserData(ctx, browser string, dataTypes []string) error
GetPrivacySettings(ctx, browser string) (*BrowserSettings, error)
```

**Command Structure**:
```bash
aftersec darkscan privacy scan --browsers chrome,firefox,safari
aftersec darkscan privacy list --severity high --type tracking-cookie
aftersec darkscan privacy remove --browser chrome --tracker-ids abc123,def456
aftersec darkscan privacy clear --browser firefox --data cookies,cache
aftersec darkscan privacy settings --browser safari
aftersec darkscan privacy telemetry --app "/Applications/Slack.app"
```

**Output Fields**:
- Browser name, finding type, severity, description
- Tracking cookie names, domains, purposes
- Extension permissions and risks
- Telemetry endpoints and data collected
- JSON/CSV export support

**Integration Points**:
- `pkg/darkscan/privacy.go` - Backend implementation
- Uses existing privacy scanner from DarkScan core

---

### 1.2 Export/Reporting Command

**File**: `cmd/aftersec/cmd/darkscan_export.go` (~200 LOC)

**DarkScan Methods to Wire**:
```go
ExportResults(ctx, scanID string, format ExportFormat) ([]byte, error)
GenerateReport(ctx, scanID string, template ReportTemplate) (*Report, error)
```

**Command Structure**:
```bash
aftersec darkscan export --scan-id abc123 --format json --output report.json
aftersec darkscan export --scan-id abc123 --format csv --output results.csv
aftersec darkscan export --scan-id abc123 --format xml --output data.xml
aftersec darkscan export --scan-id abc123 --format pdf --output report.pdf
aftersec darkscan report --scan-id abc123 --template executive-summary
```

**Formats**:
- JSON (machine-readable)
- CSV (spreadsheet import)
- XML (enterprise integration)
- PDF (executive reporting - requires PDF library)
- Text (human-readable)

**Report Templates**:
- `executive-summary` - High-level overview
- `technical-details` - Full threat analysis
- `compliance` - Regulatory compliance mapping

---

### 1.3 Profile Management Command

**File**: `cmd/aftersec/cmd/darkscan_profiles.go` (~250 LOC)

**DarkScan Methods to Wire**:
```go
ListProfiles() ([]ScanProfile, error)
GetProfile(name string) (*ScanProfile, error)
CreateCustomProfile(profile *ScanProfile) error
DeleteCustomProfile(name string) error
ApplyProfile(profileName string) error
```

**Command Structure**:
```bash
aftersec darkscan profiles list
aftersec darkscan profiles show --name forensic
aftersec darkscan profiles create --name custom-fast --engines clamav,yara --timeout 60s
aftersec darkscan profiles delete --name custom-fast
aftersec darkscan profiles apply --name deep
```

**Profile Fields**:
- Name, description, timeout
- Enabled engines (clamav, yara, capa, viper, document, heuristics)
- Max file size, recursion, follow symlinks
- Built-in protection (quick/standard/deep/forensic/safe cannot be deleted)

---

### 1.4 Rule Management Command

**File**: `cmd/aftersec/cmd/darkscan_rules.go` (~300 LOC)

**DarkScan Methods to Wire**:
```go
UpdateRules(ctx) error
ListRuleRepositories() ([]RuleRepository, error)
AddRuleRepository(ctx, url, branch string) error
RemoveRuleRepository(url string) error
GetRuleInfo() (*RuleStats, error)
```

**Command Structure**:
```bash
aftersec darkscan rules list
aftersec darkscan rules update
aftersec darkscan rules add --url https://github.com/Yara-Rules/rules --branch master
aftersec darkscan rules remove --url https://github.com/Yara-Rules/rules
aftersec darkscan rules info
```

**Output Fields**:
- Repository URL, branch, last updated
- Rule count, categories, authors
- Update status and errors
- Rule statistics (active rules, disabled rules, etc.)

---

### 1.5 Enhanced Steganography Command

**File**: Update `cmd/aftersec/cmd/darkscan_stego.go` (~150 LOC additions)

**Currently Missing**:
- Batch image scanning
- LSB analysis details
- DCT coefficient analysis
- Statistical anomaly reporting

**New Subcommands**:
```bash
aftersec darkscan stego detect --image photo.png
aftersec darkscan stego batch --directory /images --recursive
aftersec darkscan stego analyze --image photo.png --method lsb,dct,chi-square
aftersec darkscan stego export --scan-id abc123 --format json
```

---

### 1.6 Enhanced Container Scanning Command

**File**: Update `cmd/aftersec/cmd/darkscan_container.go` (~150 LOC additions)

**Currently Missing**:
- Layer-by-layer analysis
- Vulnerability database integration
- Secret scanning (API keys, tokens, passwords)
- Configuration analysis

**New Subcommands**:
```bash
aftersec darkscan container scan --image nginx:latest --layers
aftersec darkscan container vulnerabilities --image alpine:3.18
aftersec darkscan container secrets --image myapp:v1.0
aftersec darkscan container config --image redis:7
```

---

### 1.7 Hash Management Command

**File**: `cmd/aftersec/cmd/darkscan_hash.go` (~250 LOC)

**DarkScan Methods to Wire**:
```go
CheckHash(ctx, hash string) (*HashResult, error)
StoreResult(ctx, result *ScanResult) error
GetScanHistory(ctx, filters HistoryFilters) ([]ScanResult, error)
SearchHistory(ctx, query string) ([]ScanResult, error)
PruneHashStore(ctx, olderThan time.Duration) (int, error)
```

**Command Structure**:
```bash
aftersec darkscan hash check --hash sha256:abc123...
aftersec darkscan hash stats
aftersec darkscan hash export --format csv --output hashes.csv
aftersec darkscan hash prune --older-than 30d
aftersec darkscan hash search --query "malware"
```

---

## Phase 2: Fyne Desktop GUI Integration (Priority: MEDIUM)

### 2.1 Privacy Scanner Tab

**File**: `cmd/aftersec-gui/privacy.go` (~350 LOC)

**UI Layout**:
```
┌─────────────────────────────────────────────────┐
│ Privacy Scanner                                 │
├─────────────────────────────────────────────────┤
│ [x] Chrome  [ ] Firefox  [x] Safari  [ ] Edge  │
│                                                 │
│ [Scan All Browsers]  [Scan Telemetry]          │
├─────────────────────────────────────────────────┤
│ Findings:                                       │
│ ┌─────────────────────────────────────────────┐ │
│ │ 🔴 HIGH - Tracking Cookie (doubleclick.net)│ │
│ │ 🟡 MEDIUM - Extension Permission (Location)│ │
│ │ 🔵 LOW - Telemetry Endpoint (google.com)   │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ [Remove Selected]  [Clear Browser Data]        │
└─────────────────────────────────────────────────┘
```

**Implementation Pattern**:
```go
func buildPrivacyTab(w fyne.Window) fyne.CanvasObject {
    // Browser checkboxes
    chromeCheck := widget.NewCheck("Chrome", nil)
    firefoxCheck := widget.NewCheck("Firefox", nil)

    // Scan button
    btnScan := widget.NewButton("Scan All Browsers", func() {
        browsers := []string{}
        if chromeCheck.Checked { browsers = append(browsers, "chrome") }

        go func() {
            dsClient, _ := darkscan.NewClient(cfg)
            findings, err := dsClient.ScanBrowserPrivacy(ctx, browsers)

            fyne.Do(func() {
                // Update UI with findings
                for _, f := range findings {
                    card := widget.NewCard(f.Type, f.Browser,
                        widget.NewLabel(f.Description))
                    resultsBox.Add(card)
                }
            })
        }()
    })

    return container.NewBorder(topPanel, bottomPanel, nil, nil, resultsScroll)
}
```

---

### 2.2 Export/Reporting Tab

**File**: `cmd/aftersec-gui/export.go` (~200 LOC)

**UI Layout**:
```
┌─────────────────────────────────────────────────┐
│ Export & Reporting                              │
├─────────────────────────────────────────────────┤
│ Scan History:                                   │
│ ┌─────────────────────────────────────────────┐ │
│ │ [x] 2026-03-28 14:32 - Malware Scan (5 inf)│ │
│ │ [ ] 2026-03-28 12:15 - Privacy Scan (12)   │ │
│ │ [ ] 2026-03-27 09:00 - Deep Scan (0)       │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ Format: [JSON ▼]                                │
│ Output: [/Users/ryan/reports/scan.json]         │
│                                                 │
│ [Export Selected]  [Generate Report]            │
└─────────────────────────────────────────────────┘
```

---

### 2.3 Profile Manager Tab

**File**: `cmd/aftersec-gui/profiles.go` (~250 LOC)

**UI Layout**:
```
┌─────────────────────────────────────────────────┐
│ Scan Profiles                                   │
├─────────────────────────────────────────────────┤
│ Built-in Profiles:                              │
│ ┌─────────────────────────────────────────────┐ │
│ │ Quick      - Fast scan (30s, ClamAV only)   │ │
│ │ Standard   - Balanced (2min, ClamAV+YARA)   │ │
│ │ Deep       - Thorough (10min, 4 engines)    │ │
│ │ Forensic   - Complete (30min, 6 engines)    │ │
│ │ Safe       - Production (1min, ClamAV)      │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ Custom Profiles:                                │
│ ┌─────────────────────────────────────────────┐ │
│ │ my-custom  - Custom config (5min, 3 eng)    │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ [Create New]  [Edit]  [Delete]  [Apply]        │
└─────────────────────────────────────────────────┘
```

---

### 2.4 YARA Rule Manager Tab

**File**: `cmd/aftersec-gui/rules.go` (~300 LOC)

**UI Layout**:
```
┌─────────────────────────────────────────────────┐
│ YARA Rule Manager                               │
├─────────────────────────────────────────────────┤
│ Repositories:                                   │
│ ┌─────────────────────────────────────────────┐ │
│ │ ✓ Yara-Rules/rules (master) - 1,234 rules  │ │
│ │ ✓ reversinglabs/rules (main) - 567 rules   │ │
│ │ ✗ custom-repo (dev) - Update failed        │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ Last Updated: 2026-03-28 08:00 AM              │
│ Total Active Rules: 1,801                       │
│                                                 │
│ [Update All]  [Add Repository]  [Remove]        │
└─────────────────────────────────────────────────┘
```

---

### 2.5 Hash Store Viewer Tab

**File**: `cmd/aftersec-gui/hashes.go` (~200 LOC)

**UI Layout**:
```
┌─────────────────────────────────────────────────┐
│ Hash Store Manager                              │
├─────────────────────────────────────────────────┤
│ Statistics:                                     │
│   Total Hashes: 12,345                          │
│   Clean Files: 11,890 (96.3%)                   │
│   Infected Files: 455 (3.7%)                    │
│   Cache Hit Rate: 87.5%                         │
│   Database Size: 45.2 MB                        │
│                                                 │
│ Recent Scans:                                   │
│ ┌─────────────────────────────────────────────┐ │
│ │ 2026-03-28 14:32 - file.exe (INFECTED)     │ │
│ │ 2026-03-28 14:30 - document.pdf (CLEAN)    │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ [Export CSV]  [Prune Old]  [Search]            │
└─────────────────────────────────────────────────┘
```

---

## Phase 3: Next.js Web Dashboard Integration (Priority: LOW)

### 3.1 Malware Scanning Page

**File**: `aftersec-dashboard/src/app/malware-scanning/page.tsx` (~400 LOC)

**Features**:
- File/directory upload interface
- Profile selection dropdown
- Real-time scan progress with WebSocket
- Results table with threat details
- Export to JSON/CSV/XML
- Quarantine actions

**API Endpoints Needed**:
```typescript
POST /api/v1/scans/file      // Scan single file
POST /api/v1/scans/directory // Scan directory
GET  /api/v1/scans/:id       // Get scan results
POST /api/v1/scans/:id/export // Export results
```

---

### 3.2 Privacy Scanner Page

**File**: `aftersec-dashboard/src/app/privacy/page.tsx` (~350 LOC)

**Features**:
- Browser selection interface
- Privacy findings table
- Severity filtering
- Tracker removal actions
- Browser data clearing

---

### 3.3 Profile Management Page

**File**: `aftersec-dashboard/src/app/profiles/page.tsx` (~300 LOC)

**Features**:
- Profile list with details
- Create custom profile wizard
- Edit/delete actions
- Apply profile to default

---

### 3.4 YARA Rules Page

**File**: `aftersec-dashboard/src/app/rules/page.tsx` (~300 LOC)

**Features**:
- Repository list with status
- Update progress indicators
- Add/remove repositories
- Rule statistics dashboard

---

### 3.5 Hash Store Page

**File**: `aftersec-dashboard/src/app/hashes/page.tsx` (~250 LOC)

**Features**:
- Statistics dashboard
- Search interface
- Export functionality
- Pruning controls

---

## Implementation Priority Matrix

| Feature | CLI LOC | GUI LOC | Web LOC | Total LOC | Priority | User Impact |
|---------|---------|---------|---------|-----------|----------|-------------|
| Privacy Scanner | 400 | 350 | 350 | 1,100 | **CRITICAL** | Very High |
| Export/Reporting | 200 | 200 | 300 | 700 | **HIGH** | High |
| Profile Management | 250 | 250 | 300 | 800 | **HIGH** | Medium |
| Rule Management | 300 | 300 | 300 | 900 | **HIGH** | Medium |
| Hash Management | 250 | 200 | 250 | 700 | **MEDIUM** | Low |
| Enhanced Stego | 150 | - | - | 150 | **MEDIUM** | Low |
| Enhanced Container | 150 | - | - | 150 | **MEDIUM** | Medium |
| **TOTALS** | **1,700** | **1,300** | **1,500** | **4,500** | - | - |

---

## Development Sequence

### Week 1: High-Priority CLI Commands
1. ✅ Privacy Scanner CLI (400 LOC)
2. ✅ Export/Reporting CLI (200 LOC)
3. ✅ Profile Management CLI (250 LOC)
4. ✅ Rule Management CLI (300 LOC)

### Week 2: Medium-Priority CLI + Testing
5. ✅ Hash Management CLI (250 LOC)
6. ✅ Enhanced Steganography CLI (150 LOC)
7. ✅ Enhanced Container CLI (150 LOC)
8. ✅ CLI integration testing

### Week 3: Fyne Desktop GUI
9. ✅ Privacy Scanner Tab (350 LOC)
10. ✅ Export/Reporting Tab (200 LOC)
11. ✅ Profile Manager Tab (250 LOC)
12. ✅ YARA Rules Tab (300 LOC)
13. ✅ Hash Store Tab (200 LOC)

### Week 4: Next.js Web Dashboard
14. ✅ Malware Scanning Page (400 LOC)
15. ✅ Privacy Scanner Page (350 LOC)
16. ✅ Profile Management Page (300 LOC)
17. ✅ YARA Rules Page (300 LOC)
18. ✅ Hash Store Page (250 LOC)

### Week 5: Polish & Documentation
19. ✅ End-to-end testing
20. ✅ Documentation updates
21. ✅ User guides

---

## File Structure After Completion

```
aftersec/
├── cmd/aftersec/cmd/
│   ├── darkscan_privacy.go         [NEW - 400 LOC]
│   ├── darkscan_export.go          [NEW - 200 LOC]
│   ├── darkscan_profiles.go        [NEW - 250 LOC]
│   ├── darkscan_rules.go           [NEW - 300 LOC]
│   ├── darkscan_hash.go            [NEW - 250 LOC]
│   ├── darkscan_stego.go           [ENHANCED - +150 LOC]
│   └── darkscan_container.go       [ENHANCED - +150 LOC]
│
├── cmd/aftersec-gui/
│   ├── privacy.go                  [NEW - 350 LOC]
│   ├── export.go                   [NEW - 200 LOC]
│   ├── profiles.go                 [NEW - 250 LOC]
│   ├── rules.go                    [NEW - 300 LOC]
│   └── hashes.go                   [NEW - 200 LOC]
│
└── aftersec-dashboard/src/app/
    ├── malware-scanning/page.tsx   [NEW - 400 LOC]
    ├── privacy/page.tsx            [NEW - 350 LOC]
    ├── profiles/page.tsx           [NEW - 300 LOC]
    ├── rules/page.tsx              [NEW - 300 LOC]
    └── hashes/page.tsx             [NEW - 250 LOC]
```

---

## Success Criteria

✅ All 8 missing DarkScan features implemented in CLI
✅ All 5 new tabs added to Fyne Desktop GUI
✅ All 5 new pages added to Next.js Web Dashboard
✅ All features tested end-to-end
✅ Documentation updated
✅ Zero breaking changes to existing functionality
✅ Code coverage maintained at >70%

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| API breaking changes | Low | High | Version DarkScan dependency |
| GUI performance issues | Medium | Medium | Async operations, lazy loading |
| Web backend missing | High | High | Stub endpoints, mock data first |
| Timeline overrun | Medium | Low | Prioritize CLI > GUI > Web |

---

## Notes

- **DarkScan version**: Assumes `/Users/ryan/development/darkscancli` at commit HEAD
- **Testing**: Each feature requires unit tests + integration tests
- **Documentation**: Each CLI command needs help text + examples
- **Backward compatibility**: All existing features must continue working
- **Configuration**: New features use existing `~/.aftersec/config.yaml` structure

---

**Last Updated**: 2026-03-28
**Next Review**: After Week 1 completion (CLI commands)
