# DarkScan Integration with AfterSec

## Overview

AfterSec now integrates with DarkScan, a multi-engine malware scanner, providing comprehensive malware detection capabilities alongside existing forensics and AI-powered threat analysis.

## Architecture

### Integration Components

```
pkg/darkscan/
├── config.go          # DarkScan configuration structures
├── client.go          # Bridge to DarkScan library
└── integration.go     # AfterSec-specific integrations

pkg/forensics/
└── darkscan_integration.go  # Enhanced forensics with DarkScan

cmd/aftersec/cmd/
├── analyze_binary.go  # Enhanced with DarkScan Phase 6
└── malware_scan.go    # Dedicated DarkScan command

cmd/aftersecd/
└── main.go            # EDR real-time protection with DarkScan
```

### Supported Engines

DarkScan provides multi-engine malware detection with:

1. **ClamAV** - Industry-standard antivirus with extensive virus definitions
2. **YARA** - Pattern matching for malware research and detection
3. **CAPA** - Capability detection in executable files (Mandiant FLARE)
4. **Viper** - Malware analysis and management framework

## Configuration

### Enable DarkScan

Edit `~/.aftersec/config.yaml`:

```yaml
daemon:
  darkscan:
    enabled: true
    engines:
      clamav:
        enabled: true
        database_path: /usr/local/share/clamav
        auto_update: false
      yara:
        enabled: true
        rules_path: /path/to/yara/rules
      capa:
        enabled: false
        exe_path: capa
        rules_path: ""
      viper:
        enabled: false
        exe_path: viper-cli
        project_name: aftersec
```

### Install Scanning Engines

#### ClamAV (Recommended)

```bash
# macOS
brew install clamav
sudo freshclam  # Update virus definitions

# Configure in AfterSec
daemon:
  darkscan:
    engines:
      clamav:
        enabled: true
        database_path: /usr/local/share/clamav
```

#### YARA (Recommended for Custom Rules)

```bash
# macOS
brew install yara

# Download community rules
git clone https://github.com/Yara-Rules/rules.git ~/.aftersec/yara-rules

# Configure in AfterSec
daemon:
  darkscan:
    engines:
      yara:
        enabled: true
        rules_path: ~/.aftersec/yara-rules
```

#### CAPA (Advanced Capability Analysis)

```bash
# Download from https://github.com/mandiant/capa/releases
# Place in PATH or specify full path

# Configure in AfterSec
daemon:
  darkscan:
    engines:
      capa:
        enabled: true
        exe_path: /usr/local/bin/capa
        rules_path: ""  # Uses built-in rules
```

#### Viper (Malware Management)

```bash
# Install Viper framework
pip install viper-framework

# Configure in AfterSec
daemon:
  darkscan:
    engines:
      viper:
        enabled: true
        exe_path: viper-cli
        project_name: aftersec
```

## Usage

### 1. Dedicated Malware Scanning

Use the new `malware-scan` command for comprehensive multi-engine scanning:

```bash
# Scan a file
aftersec malware-scan /path/to/suspicious/file

# Scan a directory recursively
aftersec malware-scan -r /Downloads

# Update virus definitions before scanning
aftersec malware-scan --update malware.bin

# Scan an app bundle
aftersec malware-scan /Applications/Suspicious.app
```

**Output Example:**
```
🛡️  AfterSec DarkScan Multi-Engine Malware Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: /path/to/file
Engines: 2 active

🔍 Scanning file...
File: /path/to/file
Scan Duration: 1.2s
Threat Level: 🔴 HIGH

🚨 MALWARE DETECTED - 2 threat(s):

1. [ClamAV] Win.Trojan.Generic-12345
   Severity: high
   Description: Generic trojan detected

2. [YARA] Suspicious_PE_Characteristics
   Severity: medium
   Description: PE file contains suspicious characteristics
```

### 2. Enhanced Binary Analysis

The `analyze-binary` command now includes DarkScan as Phase 6:

```bash
# Full analysis including DarkScan
aftersec analyze-binary /path/to/binary

# Skip DarkScan if needed
aftersec analyze-binary --skip-darkscan /path/to/binary
```

**Analysis Phases:**
1. Cryptographic Hashing (MD5, SHA1, SHA256)
2. Code Signature Verification
3. Mach-O Structure & Capability Analysis
4. Global Threat Intelligence (FileHashes.io, DarkAPI.io)
5. String Extraction & IOC Detection
6. **Multi-Engine Malware Scanning (DarkScan)** ⬅️ NEW
7. AI-Powered Threat Analysis

### 3. Real-Time EDR Protection

The AfterSec daemon (`aftersecd`) now uses DarkScan for real-time malware detection during process execution:

```bash
# Start daemon with DarkScan protection
sudo ./aftersecd
```

**EDR Protection Layers:**
1. Local YARA Sandboxing
2. **DarkScan Multi-Engine Real-Time Protection** ⬅️ NEW (10-second timeout)
3. Cloud Detonation Engine (Enterprise Mode)

**Daemon Output:**
```
[OK] DarkScan Multi-Engine Protection Active (2 engines)

🛑 [DARKSCAN] Blocked execution: /tmp/malware.bin (Threat Level: HIGH)
⚠️ [DARKSCAN] Suspicious file allowed: /Downloads/app.dmg (Threat Level: MEDIUM)
```

### 4. Forensics Integration

Use enhanced forensics analysis with DarkScan:

```go
import (
    "aftersec/pkg/darkscan"
    "aftersec/pkg/forensics"
)

// Create DarkScan client
dsClient, err := darkscan.NewClient(config)
if err != nil {
    // Handle error
}
defer dsClient.Close()

// Perform enhanced analysis
report, err := forensics.AnalyzeWithDarkScan(ctx, "/path/to/binary", dsClient)
if err != nil {
    // Handle error
}

// Access both forensics and malware results
fmt.Printf("Forensics Threat Score: %d\n", report.ThreatScore)
fmt.Printf("DarkScan Infected: %v\n", report.DarkScanResults.Infected)
```

## API Reference

### Client Creation

```go
import "aftersec/pkg/darkscan"

// Create client with config
client, err := darkscan.NewClient(cfg)
if err != nil {
    // Handle error
}
defer client.Close()
```

### File Scanning

```go
// Scan single file
result, err := client.ScanFile(ctx, "/path/to/file")

// Scan directory
results, err := client.ScanDirectory(ctx, "/path/to/dir", true)

// Quick scan (boolean result)
infected, err := client.QuickScan(ctx, "/path/to/file")
```

### Real-Time Protection

```go
// Real-time scan with timeout and threat assessment
shouldBlock, threatLevel, err := client.RealTimeScan(ctx, "/path/to/file", 10)

if shouldBlock {
    // Block execution
}
```

### Detailed Reports

```go
// Get comprehensive report
report, err := client.ScanWithReport(ctx, "/path/to/file")

fmt.Printf("Threat Level: %s\n", report.ThreatLevel)
fmt.Printf("Scan Duration: %s\n", report.ScanDuration)
fmt.Printf("Engines: %v\n", report.Engines)

for _, threat := range report.Threats {
    fmt.Printf("[%s] %s: %s\n", threat.Engine, threat.Name, threat.Description)
}
```

## Threat Levels

DarkScan assigns threat levels based on detection results:

- **NONE** (🟢) - No threats detected
- **LOW** (🟡) - Low-severity threat or single engine detection
- **MEDIUM** (🟠) - Medium-severity threat
- **HIGH** (🔴) - High-severity threat or multi-engine detection
- **CRITICAL** (🔴) - Critical threat requiring immediate action

Multi-engine detections automatically elevate threat level for increased confidence.

## Performance Considerations

### Scanning Timeouts

- **analyze-binary command**: 60 seconds
- **EDR real-time protection**: 10 seconds
- **malware-scan command**: 2 minutes (file), 10 minutes (directory)

### Resource Usage

DarkScan engines vary in resource consumption:

- **ClamAV**: Medium CPU, high memory (virus database)
- **YARA**: Low CPU, low memory (depends on rule complexity)
- **CAPA**: High CPU, medium memory (deep analysis)
- **Viper**: Low CPU, low memory (hash lookup)

### Optimization Tips

1. **Enable only needed engines**: Start with ClamAV and YARA
2. **Use quick scans for real-time**: EDR uses optimized 10-second timeout
3. **Update definitions regularly**: Run `aftersec malware-scan --update`
4. **Tune YARA rules**: Use focused rule sets for better performance

## Integration Benefits

### Enhanced Detection

- **Multi-engine consensus**: Higher confidence with multiple detections
- **Complementary approaches**: Signature (ClamAV) + behavioral (CAPA) + pattern (YARA)
- **Real-time protection**: Block malware at execution time
- **Comprehensive analysis**: Malware detection + forensics + AI analysis

### Enterprise Features

- **EDR integration**: Automatic real-time protection
- **Telemetry logging**: All detections logged to SQLite/PostgreSQL
- **Threat intelligence**: Combined with FileHashes.io and DarkAPI.io
- **AI correlation**: Malware findings feed into AI threat analysis

### Flexibility

- **Per-engine configuration**: Enable/disable individual engines
- **Configurable thresholds**: Control blocking behavior
- **Multiple scan modes**: Quick, standard, comprehensive
- **Extensible**: Add custom YARA rules and CAPA signatures

## Troubleshooting

### DarkScan Disabled

If you see "DarkScan is disabled", enable it in config:

```yaml
daemon:
  darkscan:
    enabled: true
```

### No Engines Enabled

Enable at least one engine:

```yaml
daemon:
  darkscan:
    engines:
      clamav:
        enabled: true
        database_path: /usr/local/share/clamav
```

### ClamAV Database Not Found

Update the database path or run `freshclam`:

```bash
sudo freshclam
```

### YARA Rules Not Found

Download rules or specify correct path:

```bash
git clone https://github.com/Yara-Rules/rules.git ~/.aftersec/yara-rules
```

### Build Issues

Ensure DarkScan library is accessible:

```bash
# Check replace directive in go.mod
cat go.mod | grep darkscan

# Should show:
replace github.com/afterdarktech/darkscan => /Users/ryan/development/darkscancli

# Rebuild
go mod tidy
go build -o bin/aftersec ./cmd/aftersec
```

## Future Enhancements

- [ ] JSON output format for malware-scan command
- [ ] Automatic virus definition updates
- [ ] Custom scan profiles (quick, standard, deep)
- [ ] Quarantine functionality
- [ ] REST API for remote scanning
- [ ] Additional engine support (VirusTotal, etc.)
- [ ] Scan result caching
- [ ] Performance metrics dashboard

## References

- **DarkScan Repository**: `/Users/ryan/development/darkscancli`
- **AfterSec Documentation**: `README.md`
- **ClamAV**: https://www.clamav.net/
- **YARA**: https://virustotal.github.io/yara/
- **CAPA**: https://github.com/mandiant/capa
- **Viper**: https://viper-framework.github.io/
