# AfterSecLib SDK

`afterseclib` is a unified API gateway (SDK) designed for external Go projects to easily consume the underlying configuration engines, memory forensics, and native system tuning features of AfterSec.

## Quickstart

Import the package in your external Go project:

```go
import "github.com/my-org/aftersec/afterseclib"
```

### System Tuning & Configuration

```go
// Clear macOS system caches
err := afterseclib.ClearSystemCaches()

// Read a boolean from defaults
isEnabled := afterseclib.GetBooleanDefault("com.apple.SoftwareUpdate", "AutomaticCheckEnabled")

// Disable Dashboard and restart Dock
afterseclib.ToggleDashboard(false)

// TCP Sysctl optimization
afterseclib.SetSysctl("net.inet.tcp.delayed_ack", "0")
```

### Threat Forensics

```go
// Train the behavioral process detection baseline
afterseclib.TrainProcessBaseline()

// Scan running process memory (YARA-like string signatures + Anomaly scoring)
findings, err := afterseclib.ScanProcesses()
for _, finding := range findings {
    if finding.Score > 0 { // Suspicious or Malicious
        fmt.Printf("Malware Detected: %s (Score: %d) - Reason: %s\n", finding.Command, finding.Score, finding.Reason)
        
        // Auto-remediate (Kill)
        afterseclib.RunPrivileged(finding.KillCommand)
    }
}
```

### Continuous Syscall Telemetry

```go
alertChan := make(chan forensics.SyscallAlert, 100)
go afterseclib.StartSyscallMonitor(alertChan)

for alert := range alertChan {
    fmt.Printf("SYSCALL PATTERN DETECTED: %s\n", alert.Pattern)
}
```

### Compliance Auditing

```go
// Run Security scan against internal enterprise rules
state, err := afterseclib.RunSecurityScan()

for _, finding := range state.Findings {
    if !finding.Passed && finding.RemediationScript != "" {
        afterseclib.RunPrivileged(finding.RemediationScript)
    }
}
```
