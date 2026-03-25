# CLIENT ENHANCEMENTS PLAN
## AfterSec: CLI, GUI, and Daemon Improvements

**Date:** 2026-03-24
**Version:** 1.0
**Scope:** Client-side enhancements (works in both standalone and enterprise modes)

---

## EXECUTIVE SUMMARY

This document focuses on enhancing the AfterSec client components:
- **CLI** (`aftersec`) - Command-line interface
- **GUI** (`aftersec-gui`) - Desktop application
- **Daemon** (`aftersecd`) - Background service

All enhancements work in **both standalone and enterprise modes**.

**Timeline:** 8-12 months for full implementation

---

## 1. CLIENT ARCHITECTURE OVERVIEW

### 1.1 Current Components

```
┌─────────────────────────────────────────────────────────────┐
│  AfterSec Client Stack                                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   CLI        │  │   GUI        │  │   Daemon         │  │
│  │  (aftersec)  │  │ (aftersec-   │  │  (aftersecd)     │  │
│  │              │  │  gui)        │  │                  │  │
│  │  - Commands  │  │  - Fyne UI   │  │  - Background    │  │
│  │  - Scripting │  │  - Tabs      │  │    scanning      │  │
│  │  - Output    │  │  - Settings  │  │  - Monitoring    │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                   │             │
│         └─────────────────┴───────────────────┘             │
│                           │                                 │
│                 ┌─────────▼──────────┐                      │
│                 │   Core Engine      │                      │
│                 │  ────────────────  │                      │
│                 │  • Scanners        │                      │
│                 │  • Forensics       │                      │
│                 │  • Plugins         │                      │
│                 │  • Storage         │                      │
│                 │  • Remediation     │                      │
│                 └────────────────────┘                      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Enhancement Philosophy

1. **Mode-Agnostic:** Features work in both standalone and enterprise modes
2. **Progressive Enhancement:** Simple by default, powerful when needed
3. **Scriptable:** Everything should be automatable
4. **User-Friendly:** CLI for power users, GUI for everyone else
5. **Extensible:** Plugin system for custom features

---

## 2. CLI ENHANCEMENTS

### 2.1 Enhanced Command Structure

**Current Structure:**
```
aftersec
├── scan
├── diff
├── commit
├── history
├── restore
└── fix
```

**Enhanced Structure:**
```
aftersec
├── scan                     # Enhanced with profiles and filters
│   ├── --profile quick|standard|thorough|custom
│   ├── --category system|network|filesystem|all
│   ├── --output json|yaml|table|csv
│   └── --watch             # Continuous monitoring mode
│
├── diff                     # Enhanced comparison
│   ├── --format unified|side-by-side|json
│   ├── --ignore-category <category>
│   └── --severity-filter critical|high|medium|low
│
├── commit                   # Baseline management
│   ├── --message "reason"
│   └── --tag "v1.0"
│
├── history                  # Enhanced history
│   ├── --format table|json|timeline
│   ├── --search <query>
│   └── --since <date>
│
├── restore                  # Rollback to baseline
│   └── [index|tag]
│
├── fix                      # Auto-remediation
│   ├── [rule_name]
│   ├── --dry-run
│   ├── --all-critical
│   └── --approve-all
│
├── plugin                   # NEW: Plugin management
│   ├── list
│   ├── install <name|url>
│   ├── remove <name>
│   ├── run <name> [args...]
│   └── validate <file.star>
│
├── forensics                # NEW: Forensics commands
│   ├── scan-memory
│   ├── scan-processes
│   ├── monitor-syscalls
│   ├── check-persistence
│   └── analyze-entitlements
│
├── baseline                 # NEW: Baseline management
│   ├── create <name>
│   ├── list
│   ├── activate <name>
│   ├── compare <baseline>
│   └── export <name> --format json|yaml
│
├── report                   # NEW: Reporting
│   ├── compliance --framework CIS|NIST|SOC2
│   ├── summary
│   ├── findings --severity <level>
│   └── export --format pdf|html|json|csv
│
├── config                   # NEW: Configuration management
│   ├── show
│   ├── set <key> <value>
│   ├── get <key>
│   ├── edit
│   └── validate
│
├── daemon                   # NEW: Daemon control
│   ├── start
│   ├── stop
│   ├── restart
│   ├── status
│   ├── logs [--follow]
│   └── config
│
└── enroll                   # NEW: Enterprise enrollment
    ├── --server <url>
    ├── --token <token>
    └── --mode standalone|enterprise
```

### 2.2 Output Formats

**Structured Output for Scripting:**

```bash
# JSON output
aftersec scan --output json | jq '.findings[] | select(.severity == "critical")'

# YAML output
aftersec scan --output yaml > scan-results.yaml

# CSV output for spreadsheets
aftersec scan --output csv > findings.csv

# Table output (default, human-readable)
aftersec scan --output table

# Quiet mode (just exit codes)
aftersec scan --quiet && echo "All checks passed"
```

**Example JSON Output:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-03-24T15:30:00Z",
  "hostname": "macbook-pro",
  "platform": "macos",
  "platform_version": "14.4",
  "agent_version": "2.0.0",
  "scan_duration_ms": 4523,
  "summary": {
    "total": 45,
    "passed": 38,
    "failed": 7,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 0
  },
  "findings": [
    {
      "id": "f1",
      "category": "system",
      "name": "SIP Status",
      "description": "System Integrity Protection is disabled",
      "severity": "critical",
      "passed": false,
      "current_value": "disabled",
      "expected_value": "enabled",
      "remediation": "csrutil enable",
      "cis_benchmark": "1.1",
      "compliance": ["CIS", "NIST-800-53"]
    }
  ]
}
```

### 2.3 Interactive Mode

**New Feature: Interactive Shell**

```bash
# Launch interactive mode
aftersec shell

# Interactive prompt
aftersec> scan --profile quick
Running quick scan...
✓ 45/45 checks complete (3 failed)

aftersec> show failures
[CRITICAL] SIP disabled
[HIGH] Firewall inactive
[HIGH] Gatekeeper disabled

aftersec> fix "SIP Status" --dry-run
Would execute: csrutil enable
Requires reboot: yes

aftersec> baseline create "before-fix"
Baseline created: before-fix

aftersec> fix "SIP Status"
This will reboot your system. Continue? (y/n): y
```

### 2.4 Scripting Support

**Shell Completion:**
```bash
# Bash
aftersec completion bash > /etc/bash_completion.d/aftersec

# Zsh
aftersec completion zsh > "${fpath[1]}/_aftersec"

# Fish
aftersec completion fish > ~/.config/fish/completions/aftersec.fish
```

**Exit Codes:**
- `0` - Success, all checks passed
- `1` - General error
- `2` - Configuration error
- `10` - Critical findings detected
- `11` - High severity findings detected
- `12` - Medium severity findings detected

**Example Automation:**
```bash
#!/bin/bash
# Daily security check script

# Run scan
if ! aftersec scan --quiet --severity-filter critical; then
    # Critical issues found
    aftersec report summary | mail -s "CRITICAL: Security Issues" admin@company.com
    exit 1
fi

# Create daily baseline
aftersec commit --message "Daily baseline $(date +%Y-%m-%d)"

# Compare with yesterday
if aftersec diff --severity-filter high --quiet; then
    echo "No significant changes"
else
    echo "Changes detected, review required"
    aftersec diff --format unified | mail -s "Security Drift Detected" admin@company.com
fi
```

### 2.5 Watch Mode

**Continuous Monitoring:**

```bash
# Watch for configuration changes
aftersec scan --watch --interval 60s

# Watch specific categories
aftersec scan --watch --category network --interval 30s

# Watch and alert
aftersec scan --watch --alert-command 'notify-send "Security Alert" "$FINDING"'
```

### 2.6 CLI Configuration

**`~/.aftersec/cli-config.yaml`:**

```yaml
# Default output format
default_output: table

# Default scan profile
default_scan_profile: standard

# Color output
colors: true

# Paging for long output
paging: auto  # auto, always, never

# Time format
time_format: "2006-01-02 15:04:05"

# Default editor for interactive commands
editor: vim

# Aliases
aliases:
  quick: scan --profile quick
  critical: scan --severity-filter critical
  daily: commit --message "Daily checkpoint"

# Notification settings
notifications:
  enabled: true
  on_critical: true
  on_high: false
  command: 'osascript -e "display notification \"$MESSAGE\" with title \"AfterSec\""'
```

---

## 3. GUI ENHANCEMENTS

### 3.1 Modern UI Redesign

**Current Layout (Fyne):**
- Scanner Tab
- Diff & Commit Tab
- History Tab
- Settings Tab

**Enhanced Layout:**

```
┌─────────────────────────────────────────────────────────────────────┐
│  AfterSec                                     [≡] [○] [□] [×]      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │Dashboard │ │ Scanner  │ │ Findings │ │Forensics │ │ Settings │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                        DASHBOARD                               │ │
│  ├────────────────────────────────────────────────────────────────┤ │
│  │                                                                 │ │
│  │  Security Score: 92/100                    [●] All systems OK  │ │
│  │  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                                         │ │
│  │                                                                 │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐ │ │
│  │  │  Critical: 0     │  │  High: 2         │  │  Medium: 5   │ │ │
│  │  │  ✓ All Clear     │  │  ⚠ Review Needed │  │  ℹ Info      │ │ │
│  │  └──────────────────┘  └──────────────────┘  └──────────────┘ │ │
│  │                                                                 │ │
│  │  Recent Scans:                         Last Scan: 2 hours ago  │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │ [Chart showing scan history over time]                  │  │ │
│  │  │                                                          │  │ │
│  │  │      ●                                                   │  │ │
│  │  │     ╱ ╲     ●                                           │  │ │
│  │  │    ╱   ╲   ╱ ╲   ●                                      │  │ │
│  │  │   ●     ╲ ╱   ╲ ╱ ╲                                     │  │ │
│  │  │          ●     ●   ●                                     │  │ │
│  │  │  ────────────────────────────────────────────────────   │  │ │
│  │  │   Mon  Tue  Wed  Thu  Fri  Sat  Sun                     │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  │                                                                 │ │
│  │  Quick Actions:                                                │ │
│  │  [Run Scan] [View Findings] [Check Baseline] [Export Report]  │ │
│  │                                                                 │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

### 3.2 Scanner Tab Enhancements

**Features:**
- **Scan Profiles:** Quick, Standard, Thorough, Custom
- **Category Selection:** Choose which security areas to scan
- **Real-time Progress:** Live updates with detailed progress
- **Estimated Time:** Show remaining time
- **Pause/Resume:** Ability to pause long-running scans
- **Scan History:** Quick access to previous scans

**UI Mockup:**

```
┌─────────────────────────────────────────────────────────────┐
│  SCANNER                                                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Scan Profile:  [Standard ▼]                                │
│                                                              │
│  Categories:    [✓] System Security                         │
│                 [✓] Network Configuration                   │
│                 [✓] Filesystem Permissions                  │
│                 [✓] Application Security                    │
│                 [ ] Custom Plugins                          │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Scanning: Network Configuration                     │   │
│  │  ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░ 45% (23/51 checks)         │   │
│  │  Current: Checking Firewall Rules                    │   │
│  │  Elapsed: 00:02:15  Remaining: ~00:02:45             │   │
│  │                                                       │   │
│  │  [Pause]  [Cancel]                                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Recent Findings:                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ [!] CRITICAL  SIP Disabled                           │   │
│  │ [!] HIGH      Firewall Inactive                      │   │
│  │ [i] MEDIUM    SSH Password Auth Enabled              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  [Start Scan]  [Save as Profile]  [Schedule...]            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Findings Tab (New)

**Features:**
- **Filter by Severity:** Critical, High, Medium, Low
- **Filter by Category:** System, Network, Filesystem, etc.
- **Filter by Status:** Unresolved, Resolved, Ignored
- **Search:** Full-text search across findings
- **Bulk Actions:** Fix multiple findings at once
- **Export:** Export findings to CSV, PDF, JSON

**UI Mockup:**

```
┌─────────────────────────────────────────────────────────────┐
│  FINDINGS                                                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [Search findings...]                [Export ▼]  [Fix All]  │
│                                                              │
│  Filters:  [All ▼] [All Categories ▼] [Unresolved ▼]       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Critical (2)  |  High (5)  |  Medium (12)  |  Low (3)│   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─[✓]──────────────────────────────────────────────────┐   │
│  │ [!] CRITICAL  System Integrity Protection Disabled   │   │
│  │     Expected: enabled  |  Current: disabled           │   │
│  │     CIS Benchmark: 1.1  |  NIST: AC-3                │   │
│  │     [View Details]  [Fix Now]  [Ignore]              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─[ ]──────────────────────────────────────────────────┐   │
│  │ [!] CRITICAL  Firewall Disabled                      │   │
│  │     Expected: enabled  |  Current: disabled           │   │
│  │     CIS Benchmark: 2.1  |  NIST: SC-7                │   │
│  │     [View Details]  [Fix Now]  [Ignore]              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─[ ]──────────────────────────────────────────────────┐   │
│  │ [⚠] HIGH  Gatekeeper Disabled                        │   │
│  │     Expected: enabled  |  Current: disabled           │   │
│  │     [View Details]  [Fix Now]  [Ignore]              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  [2 selected]  [Fix Selected]  [Ignore Selected]           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.4 Forensics Tab (New)

**Features:**
- **Memory Scanning:** Scan running processes for threats
- **Syscall Monitoring:** Real-time system call monitoring
- **Persistence Check:** Detect persistence mechanisms
- **Process Analysis:** Behavioral analysis of processes
- **Live Alerts:** Real-time threat notifications

**UI Mockup:**

```
┌─────────────────────────────────────────────────────────────┐
│  FORENSICS                                                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [Scan Memory]  [Monitor Syscalls]  [Check Persistence]    │
│                                                              │
│  Active Monitors:                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ [●] Syscall Monitor    Running for 2h 34m            │   │
│  │     Events: 1,234  |  Alerts: 3                      │   │
│  │     [View Alerts]  [Stop]                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Recent Alerts:                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ [!] Suspicious syscall pattern detected              │   │
│  │     Process: unknown_binary (PID 12345)               │   │
│  │     Pattern: exec+fork+network                        │   │
│  │     Time: 2026-03-24 15:23:45                        │   │
│  │     [Investigate]  [Kill Process]  [Ignore]          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ [!] Memory signature match                            │   │
│  │     Process: malware.app (PID 67890)                  │   │
│  │     Signature: Trojan.Generic                         │   │
│  │     Confidence: High (87%)                            │   │
│  │     [Investigate]  [Kill Process]  [Quarantine]      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Process Monitor:                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ PID   | Process Name      | CPU  | Memory | Status   │   │
│  │ 12345 | unknown_binary    | 45%  | 234 MB | ⚠ Susp  │   │
│  │ 67890 | malware.app       | 12%  | 123 MB | ⚠ Susp  │   │
│  │ 11111 | normal_app        | 2%   | 45 MB  | ✓ OK    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.5 Baseline & Drift Tab (Enhanced)

**Features:**
- **Visual Timeline:** See baseline history over time
- **Drift Detection:** Highlight changes from baseline
- **Comparison View:** Side-by-side comparison
- **Auto-baseline:** Automatic baseline creation
- **Restore:** One-click restore to baseline

### 3.6 Settings Tab Enhancements

**Categories:**
- **General:** Mode (standalone/enterprise), Auto-start
- **Scanning:** Default profile, Scan schedule, Categories
- **Notifications:** Desktop notifications, Email alerts
- **Plugins:** Manage Starlark plugins
- **Appearance:** Theme (light/dark/auto), Font size
- **Advanced:** Debug mode, Log level, Storage location
- **Enterprise:** Server connection, Enrollment status

### 3.7 System Tray Integration

**Features:**
- Live in system tray/menu bar
- Quick status indicator (green/yellow/red)
- Quick actions menu
- Notifications for critical findings

**Menu Bar:**
```
  [AfterSec Icon - Green]
  ├─ Security Status: OK
  ├─ Last Scan: 2 hours ago
  ├─ ───────────────────────
  ├─ Quick Scan
  ├─ View Dashboard
  ├─ ───────────────────────
  ├─ Settings
  └─ Quit
```

### 3.8 Dark Mode

**Full dark mode support with automatic theme switching**

---

## 4. DAEMON ENHANCEMENTS

### 4.1 Enhanced Scheduling

**Current:** Fixed 6-hour interval

**Enhanced:**

```yaml
# ~/.aftersec/daemon-config.yaml
scheduling:
  # Scan intervals
  scan_interval: 6h           # Regular scans
  quick_scan_interval: 1h     # Quick scans (subset of checks)

  # Adaptive scheduling based on risk
  adaptive: true
  high_risk_interval: 30m     # If critical findings detected
  normal_interval: 6h
  low_risk_interval: 24h

  # Time windows
  quiet_hours:
    enabled: true
    start: "22:00"
    end: "08:00"

  # Maintenance windows (no scans)
  maintenance_windows:
    - start: "2026-03-25T00:00:00Z"
      end: "2026-03-25T04:00:00Z"
      reason: "System maintenance"
```

### 4.2 Resource Management

**CPU/Memory Throttling:**

```yaml
resources:
  # CPU limits
  max_cpu_percent: 25         # Don't exceed 25% CPU
  nice_level: 10              # Run at lower priority

  # Memory limits
  max_memory_mb: 500          # Don't exceed 500MB

  # I/O limits
  io_priority: low

  # Scan throttling
  pause_on_battery: true      # Pause scans when on battery
  pause_on_high_load: true    # Pause if system load > 0.8
```

### 4.3 Intelligent Scanning

**Priority-Based Scanning:**

```yaml
scan_strategy:
  # Check critical items more frequently
  critical_checks_interval: 15m

  # Prioritize based on previous failures
  rescan_failures: true
  rescan_failures_interval: 1h

  # Skip checks that always pass
  skip_stable_checks: true
  stable_threshold: 10        # 10 consecutive passes
```

### 4.4 Advanced Monitoring

**Syscall Monitoring Configuration:**

```yaml
syscall_monitor:
  enabled: true

  # Patterns to watch for
  patterns:
    - name: "suspicious_exec_chain"
      syscalls: ["execve", "fork", "connect"]
      threshold: 3
      severity: high
      action: alert

    - name: "privilege_escalation"
      syscalls: ["setuid", "setgid", "seteuid"]
      threshold: 1
      severity: critical
      action: alert_and_log

  # Performance tuning
  buffer_size: 10000
  flush_interval: 10s

  # Filtering
  exclude_processes:
    - "/usr/bin/bash"
    - "/usr/sbin/systemd"
```

### 4.5 Alert Management

**Multi-Channel Alerting:**

```yaml
alerts:
  # Severity thresholds
  alert_on_critical: true
  alert_on_high: true
  alert_on_medium: false

  # Channels
  channels:
    - type: desktop_notification
      enabled: true
      severities: [critical, high]

    - type: email
      enabled: true
      severities: [critical]
      to: "admin@company.com"
      smtp:
        host: smtp.gmail.com
        port: 587
        username: alerts@company.com
        password_env: SMTP_PASSWORD

    - type: slack
      enabled: false
      webhook_url_env: SLACK_WEBHOOK_URL
      severities: [critical, high]

    - type: webhook
      enabled: false
      url: https://alerts.company.com/webhook
      method: POST
      headers:
        Authorization: "Bearer ${WEBHOOK_TOKEN}"
      severities: [critical, high, medium]

    - type: syslog
      enabled: true
      facility: local0
      severities: [critical, high]
```

### 4.6 Automatic Remediation

**Safe Auto-Remediation:**

```yaml
auto_remediation:
  enabled: false              # Disabled by default for safety

  # Whitelist of safe remediations
  allowed_remediations:
    - "enable_firewall"
    - "enable_gatekeeper"
    - "update_system_defaults"

  # Blacklist of dangerous remediations
  forbidden_remediations:
    - "enable_sip"            # Requires reboot
    - "disable_services"      # Could break things

  # Require approval for critical changes
  require_approval_for:
    - severity: critical
    - requires_reboot: true
    - affects_networking: true

  # Create baseline before remediation
  backup_before_remediation: true

  # Rollback on failure
  auto_rollback: true
  rollback_timeout: 5m        # Rollback if issues detected within 5min
```

### 4.7 Logging & Diagnostics

**Enhanced Logging:**

```yaml
logging:
  # Log levels
  level: info                 # debug, info, warn, error

  # Output destinations
  outputs:
    - type: file
      path: /var/log/aftersecd.log
      max_size_mb: 100
      max_backups: 5
      compress: true

    - type: stdout
      format: text            # text or json

    - type: syslog
      facility: local0

  # Structured logging
  format: json

  # Performance logging
  log_scan_duration: true
  log_slow_queries: true
  slow_query_threshold: 1s

  # Audit logging
  audit_log: /var/log/aftersecd-audit.log
  audit_events:
    - remediation_executed
    - configuration_changed
    - baseline_created
    - alert_triggered
```

### 4.8 Health Checks & Self-Monitoring

**Daemon Self-Monitoring:**

```yaml
health_checks:
  enabled: true
  interval: 5m

  checks:
    - name: memory_usage
      threshold: 500MB
      action: log_warning

    - name: cpu_usage
      threshold: 50%
      action: log_warning

    - name: disk_space
      threshold: 90%
      action: pause_scans

    - name: last_successful_scan
      threshold: 24h
      action: alert

  # Self-healing
  auto_restart_on_crash: true
  max_restart_attempts: 3
  restart_backoff: exponential
```

### 4.9 Plugin Management

**Daemon Plugin System:**

```yaml
plugins:
  enabled: true
  plugin_dir: ~/.aftersec/plugins

  # Plugin execution
  timeout: 30s
  max_concurrent: 5

  # Security
  sandbox: true
  allow_network: false
  allow_file_write: false

  # Auto-load plugins on startup
  auto_load:
    - custom-security-check.star
    - company-compliance.star

  # Plugin scheduling
  scheduled_plugins:
    - name: daily-backup-check
      plugin: backup-validator.star
      schedule: "0 9 * * *"     # Daily at 9 AM

    - name: weekly-audit
      plugin: audit-generator.star
      schedule: "0 0 * * 0"     # Weekly on Sunday
```

---

## 5. PLUGIN SYSTEM ENHANCEMENTS

### 5.1 Enhanced Starlark API

**Current API:** Basic

**Enhanced API:**

```python
# ~/.aftersec/plugins/custom-check.star

# Enhanced API with more capabilities
load("aftersec.star", "security", "system", "network", "process", "report")

def check_custom_security():
    """Custom security check with full API access"""

    # System information
    os_version = system.version()
    hostname = system.hostname()
    uptime = system.uptime()

    # File system checks
    if not system.file_exists("/etc/custom-security.conf"):
        report.finding(
            category="custom",
            name="Custom Security Config Missing",
            severity="high",
            current="not found",
            expected="exists",
            remediation="touch /etc/custom-security.conf"
        )

    # Network checks
    open_ports = network.listening_ports()
    for port in open_ports:
        if port.number > 10000 and not port.process_authorized:
            report.finding(
                category="network",
                name=f"Unauthorized service on port {port.number}",
                severity="medium",
                current=f"{port.process} listening on {port.number}",
                expected="no unauthorized services"
            )

    # Process checks
    processes = process.list()
    for proc in processes:
        if "crypto" in proc.name.lower() and proc.user != "system":
            report.finding(
                category="process",
                name="Unauthorized cryptocurrency miner",
                severity="critical",
                current=f"{proc.name} running as {proc.user}",
                expected="no crypto miners",
                remediation=f"kill -9 {proc.pid}"
            )

    # Certificate checks
    certs = security.certificates()
    for cert in certs:
        if cert.expires_in_days < 30:
            report.finding(
                category="certificates",
                name=f"Certificate {cert.name} expiring soon",
                severity="high",
                current=f"expires in {cert.expires_in_days} days",
                expected="at least 30 days until expiry"
            )

    # Custom compliance check
    compliance_items = [
        ("SIP", security.sip_enabled()),
        ("Firewall", security.firewall_enabled()),
        ("FileVault", security.filevault_enabled()),
    ]

    score = sum(1 for _, enabled in compliance_items if enabled)
    total = len(compliance_items)

    if score < total:
        report.finding(
            category="compliance",
            name="Company Security Baseline",
            severity="high" if score < total * 0.7 else "medium",
            current=f"{score}/{total} requirements met",
            expected=f"{total}/{total} requirements met"
        )

    return report.summary()

# Entry point
main = check_custom_security
```

**New Starlark Modules:**

```python
# System module
system.version()              # OS version
system.hostname()             # Hostname
system.uptime()               # System uptime
system.kernel_version()       # Kernel version
system.file_exists(path)      # Check file existence
system.file_permissions(path) # Get file permissions
system.read_file(path)        # Read file (sandboxed)
system.exec(cmd, args)        # Execute command (restricted)

# Network module
network.interfaces()          # Network interfaces
network.listening_ports()     # Open ports
network.connections()         # Active connections
network.firewall_rules()      # Firewall rules
network.dns_servers()         # DNS configuration

# Process module
process.list()                # All processes
process.find(name)            # Find by name
process.get(pid)              # Get by PID
process.tree()                # Process tree
process.memory_usage(pid)     # Memory usage
process.cpu_usage(pid)        # CPU usage

# Security module
security.sip_enabled()        # SIP status
security.firewall_enabled()   # Firewall status
security.gatekeeper_enabled() # Gatekeeper status
security.filevault_enabled()  # FileVault status
security.certificates()       # Installed certificates
security.keychain_items()     # Keychain entries

# Report module
report.finding(               # Add finding
    category="",
    name="",
    severity="",
    current="",
    expected="",
    remediation=""
)
report.summary()              # Get summary
report.metric(name, value)    # Add custom metric
```

### 5.2 Plugin Repository

**Community Plugin Marketplace:**

```bash
# List available plugins
aftersec plugin search <query>

# Install from repository
aftersec plugin install github.com/aftersec-plugins/cis-benchmark

# Install from local file
aftersec plugin install ./custom-check.star

# List installed plugins
aftersec plugin list

# Run specific plugin
aftersec plugin run cis-benchmark

# Update plugins
aftersec plugin update --all
```

**Plugin Manifest:**

```yaml
# plugin.yaml
name: cis-macos-benchmark
version: 1.0.0
description: CIS Benchmark checks for macOS
author: AfterSec Community
license: MIT
homepage: https://github.com/aftersec-plugins/cis-benchmark

# Plugin file
script: cis-benchmark.star

# Minimum AfterSec version
min_version: 2.0.0

# Permissions required
permissions:
  - system:read
  - network:read
  - process:read

# Dependencies
dependencies:
  - common-checks@1.2.0
```

### 5.3 Plugin Development Tools

**Plugin Validator:**

```bash
# Validate plugin syntax and security
aftersec plugin validate custom-check.star

# Output:
# ✓ Syntax valid
# ✓ No security issues
# ✓ API usage correct
# ⚠ Warning: network.exec() usage detected
```

**Plugin Testing Framework:**

```python
# custom-check_test.star

load("test.star", "assert", "mock")
load("custom-check.star", "check_custom_security")

def test_detects_missing_config():
    # Mock file system
    mock.file_exists("/etc/custom-security.conf", False)

    # Run check
    result = check_custom_security()

    # Assert finding was reported
    assert.contains(result.findings, "Custom Security Config Missing")
    assert.equal(result.findings[0].severity, "high")

def test_allows_authorized_ports():
    # Mock network state
    mock.listening_ports([
        {"number": 22, "process": "sshd", "authorized": True},
        {"number": 443, "process": "nginx", "authorized": True}
    ])

    result = check_custom_security()

    # Should not report findings for authorized ports
    assert.empty(result.findings)

# Run tests
test.run()
```

---

## 6. CONFIGURATION ENHANCEMENTS

### 6.1 Hierarchical Configuration

**Configuration Precedence:**

1. Command-line flags (highest priority)
2. Environment variables
3. User config (`~/.aftersec/config.yaml`)
4. System config (`/etc/aftersec/config.yaml`)
5. Default values (lowest priority)

**Environment Variables:**

```bash
# Mode
AFTERSEC_MODE=enterprise

# Server connection (enterprise mode)
AFTERSEC_SERVER_URL=grpc.company.com:443
AFTERSEC_ENROLLMENT_TOKEN=eyJhbG...

# Scanning
AFTERSEC_SCAN_INTERVAL=6h
AFTERSEC_SCAN_PROFILE=standard

# Logging
AFTERSEC_LOG_LEVEL=info
AFTERSEC_LOG_FORMAT=json

# Storage
AFTERSEC_STORAGE_PATH=~/.aftersec
```

### 6.2 Configuration Validation

```bash
# Validate configuration
aftersec config validate

# Output:
# ✓ Configuration valid
# ✓ All required fields present
# ✓ Server connection successful (enterprise mode)
# ⚠ Warning: scan_interval very high (24h)
```

### 6.3 Configuration Templates

**Built-in Templates:**

```bash
# Generate configuration for specific use case
aftersec config init --template developer
aftersec config init --template enterprise
aftersec config init --template paranoid
aftersec config init --template minimal
```

**Developer Template:**
```yaml
# Optimized for developers
mode: standalone
scan_interval: 12h
scan_profile: standard
quiet_hours:
  enabled: true
  start: "09:00"
  end: "18:00"
auto_remediation:
  enabled: false
```

**Paranoid Template:**
```yaml
# Maximum security
mode: standalone
scan_interval: 1h
scan_profile: thorough
auto_remediation:
  enabled: true
alerts:
  alert_on_medium: true
syscall_monitor:
  enabled: true
```

---

## 7. EXPORT & REPORTING

### 7.1 Report Formats

**PDF Reports:**

```bash
# Generate PDF report
aftersec report export --format pdf --output security-report.pdf

# Include specific sections
aftersec report export --format pdf \
  --include summary,findings,compliance \
  --output report.pdf

# Custom branding
aftersec report export --format pdf \
  --logo company-logo.png \
  --title "Q1 2026 Security Audit" \
  --output q1-audit.pdf
```

**HTML Reports:**

```bash
# Interactive HTML report
aftersec report export --format html --output report.html

# Self-contained (embedded CSS/JS)
aftersec report export --format html --self-contained --output report.html
```

**Excel Reports:**

```bash
# Excel spreadsheet with multiple sheets
aftersec report export --format xlsx --output findings.xlsx

# Sheets: Summary, Findings, History, Compliance
```

### 7.2 Compliance Reports

**CIS Benchmark:**

```bash
# CIS macOS benchmark report
aftersec report compliance --framework CIS --output cis-report.pdf

# Include evidence
aftersec report compliance --framework CIS --include-evidence
```

**NIST 800-53:**

```bash
# NIST controls mapping
aftersec report compliance --framework NIST-800-53 --output nist-report.pdf
```

**SOC2:**

```bash
# SOC2 evidence collection
aftersec report compliance --framework SOC2 \
  --start-date 2026-01-01 \
  --end-date 2026-03-31 \
  --output soc2-evidence.pdf
```

### 7.3 Automated Reporting

**Scheduled Reports:**

```yaml
# ~/.aftersec/reporting.yaml
reports:
  - name: daily_summary
    schedule: "0 9 * * *"     # Daily at 9 AM
    format: email
    template: summary
    recipients:
      - security-team@company.com

  - name: weekly_compliance
    schedule: "0 9 * * 1"     # Monday at 9 AM
    format: pdf
    framework: CIS
    output: /reports/weekly-cis-{date}.pdf

  - name: monthly_audit
    schedule: "0 9 1 * *"     # 1st of month at 9 AM
    format: xlsx
    include:
      - summary
      - findings
      - history
      - compliance
    output: /reports/monthly-{year}-{month}.xlsx
```

---

## 8. PERFORMANCE OPTIMIZATIONS

### 8.1 Scan Performance

**Optimizations:**

- **Parallel Scanning:** Run independent checks concurrently
- **Caching:** Cache results for expensive checks
- **Incremental Scans:** Only re-check changed items
- **Smart Scheduling:** Run heavy checks during low usage

**Configuration:**

```yaml
performance:
  # Parallel execution
  max_concurrent_checks: 10

  # Caching
  cache_enabled: true
  cache_ttl: 1h
  cache_expensive_checks: true

  # Incremental scanning
  incremental: true

  # Resource limits
  max_cpu_percent: 25
  max_memory_mb: 500
```

### 8.2 Storage Optimization

**Compression & Retention:**

```yaml
storage:
  # Compress old scan results
  compress_after: 7d
  compression_level: 6        # 1-9, higher = better compression

  # Retention policy
  retention:
    keep_recent: 100          # Keep last 100 scans
    keep_daily: 30            # Keep 1 per day for 30 days
    keep_weekly: 52           # Keep 1 per week for 52 weeks
    keep_monthly: 24          # Keep 1 per month for 24 months

  # Deduplicate identical findings
  deduplicate: true
```

---

## 9. ACCESSIBILITY & LOCALIZATION

### 9.1 Accessibility

**GUI Features:**
- High contrast mode
- Keyboard navigation
- Screen reader support
- Adjustable font sizes
- Color-blind friendly palette

### 9.2 Localization

**Supported Languages:**
- English (default)
- Spanish
- French
- German
- Japanese
- Chinese (Simplified)

**Configuration:**

```yaml
localization:
  language: en              # en, es, fr, de, ja, zh
  date_format: YYYY-MM-DD
  time_format: 24h          # 12h or 24h
  timezone: auto            # auto or specific (America/New_York)
```

---

## 10. IMPLEMENTATION ROADMAP

### Phase 1: Core CLI Enhancements (Months 1-2)

**Deliverables:**
- Enhanced command structure
- Multiple output formats (JSON, YAML, CSV)
- Exit codes for scripting
- Shell completion
- Watch mode
- Interactive mode

**Files to Modify/Create:**
```
cmd/aftersec/
├── main.go                   # MODIFY: Add new commands
└── commands/
    ├── scan.go               # ENHANCE: Add profiles, filters
    ├── report.go             # NEW: Reporting commands
    ├── plugin.go             # NEW: Plugin management
    ├── forensics.go          # NEW: Forensics commands
    ├── baseline.go           # NEW: Baseline management
    └── shell.go              # NEW: Interactive mode

pkg/cli/
├── output/
│   ├── json.go               # NEW: JSON formatter
│   ├── yaml.go               # NEW: YAML formatter
│   ├── csv.go                # NEW: CSV formatter
│   └── table.go              # ENHANCE: Better tables
└── completion/
    ├── bash.go               # NEW: Bash completion
    ├── zsh.go                # NEW: Zsh completion
    └── fish.go               # NEW: Fish completion
```

---

### Phase 2: Daemon Enhancements (Months 3-4)

**Deliverables:**
- Intelligent scheduling
- Resource management
- Advanced alerting
- Auto-remediation framework
- Enhanced logging

**Files to Modify/Create:**
```
cmd/aftersecd/
└── main.go                   # MODIFY: Enhanced daemon

pkg/daemon/
├── scheduler.go              # ENHANCE: Intelligent scheduling
├── resources.go              # NEW: Resource management
├── alerts.go                 # NEW: Multi-channel alerting
├── remediation.go            # NEW: Auto-remediation
└── health.go                 # NEW: Self-monitoring

pkg/config/
└── daemon.go                 # NEW: Daemon configuration
```

---

### Phase 3: GUI Redesign (Months 5-7)

**Deliverables:**
- Modern UI redesign
- Dashboard tab
- Enhanced scanner tab
- New findings tab
- Forensics tab
- System tray integration
- Dark mode

**Files to Modify/Create:**
```
cmd/aftersec-gui/
└── main.go                   # MODIFY: New UI layout

internal/gui/
├── dashboard.go              # NEW: Dashboard tab
├── scanner.go                # ENHANCE: Better scanner UI
├── findings.go               # NEW: Findings tab
├── forensics.go              # NEW: Forensics tab
├── baseline.go               # ENHANCE: Better baseline UI
├── settings.go               # ENHANCE: More settings
├── theme.go                  # NEW: Dark mode support
└── tray.go                   # NEW: System tray
```

---

### Phase 4: Plugin System (Months 8-9)

**Deliverables:**
- Enhanced Starlark API
- Plugin marketplace
- Plugin development tools
- Plugin testing framework
- Example plugins

**Files to Create:**
```
pkg/plugins/
├── api.go                    # ENHANCE: Enhanced API
├── marketplace.go            # NEW: Plugin marketplace
├── validator.go              # NEW: Plugin validation
└── testing.go                # NEW: Test framework

plugins/
├── examples/
│   ├── cis-benchmark.star
│   ├── custom-checks.star
│   └── compliance.star
└── testing/
    └── test-helpers.star
```

---

### Phase 5: Reporting & Export (Months 10-11)

**Deliverables:**
- PDF reports
- HTML reports
- Excel exports
- Compliance reports
- Automated reporting

**Files to Create:**
```
pkg/report/
├── pdf.go                    # NEW: PDF generation
├── html.go                   # NEW: HTML reports
├── xlsx.go                   # NEW: Excel export
├── compliance/
│   ├── cis.go                # NEW: CIS reports
│   ├── nist.go               # NEW: NIST reports
│   └── soc2.go               # NEW: SOC2 reports
└── scheduler.go              # NEW: Scheduled reports
```

---

### Phase 6: Polish & Performance (Month 12)

**Deliverables:**
- Performance optimizations
- Bug fixes
- Documentation
- Localization
- Accessibility improvements

---

## 11. SUCCESS METRICS

### 11.1 Performance Metrics

- **Scan Duration:** < 3 minutes (standard profile)
- **Memory Usage:** < 300MB during scan
- **CPU Usage:** < 20% during scan
- **GUI Responsiveness:** < 100ms for UI interactions

### 11.2 User Experience Metrics

- **Time to First Scan:** < 2 minutes (from install)
- **Learning Curve:** < 30 minutes to basic proficiency
- **Configuration Time:** < 5 minutes for typical setup
- **Error Rate:** < 1% of scans fail

### 11.3 Adoption Metrics

- **CLI Usage:** 60% of users
- **GUI Usage:** 80% of users
- **Plugin Usage:** 30% of users
- **Scheduled Scans:** 70% of installations

---

## 12. TESTING STRATEGY

### 12.1 CLI Testing

- Unit tests for all commands
- Integration tests for output formats
- Scripting scenario tests
- Performance benchmarks

### 12.2 GUI Testing

- Unit tests for UI components
- Integration tests for workflows
- Visual regression tests
- Accessibility testing

### 12.3 Daemon Testing

- Long-running stability tests
- Resource usage monitoring
- Scheduling accuracy tests
- Alert delivery tests

---

## 13. DOCUMENTATION

### 13.1 User Documentation

```
docs/
├── cli/
│   ├── quickstart.md
│   ├── commands.md
│   ├── scripting.md
│   └── examples.md
├── gui/
│   ├── getting-started.md
│   ├── features.md
│   └── screenshots/
└── daemon/
    ├── installation.md
    ├── configuration.md
    └── troubleshooting.md
```

### 13.2 Developer Documentation

```
docs/dev/
├── plugin-development.md
├── starlark-api.md
├── contributing.md
└── architecture.md
```

---

## CONCLUSION

These client enhancements will make AfterSec:

1. **More Powerful:** Enhanced CLI for automation and scripting
2. **More User-Friendly:** Modern GUI with intuitive workflows
3. **More Intelligent:** Smart daemon with adaptive scanning
4. **More Extensible:** Robust plugin system with marketplace
5. **More Professional:** Comprehensive reporting and compliance

All features work in **both standalone and enterprise modes**, providing immediate value regardless of deployment type.

**Timeline:** 12 months for full implementation
**Team:** 2-3 engineers

Ready to transform AfterSec into a best-in-class security tool!
