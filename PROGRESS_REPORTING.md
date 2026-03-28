# Progress Reporting for GUI Integration

## Overview

The AfterSec malware scanner now supports real-time progress reporting through JSON events emitted to stderr. This allows GUI applications to monitor scan progress, display real-time status, and show results as they're discovered.

## Implementation

Based on the DarkScan CLI progress reporting system, AfterSec now includes:

### Files Added/Modified:
- **`pkg/darkscan/progress.go`** - Progress reporter module
- **`cmd/aftersec/cmd/malware_scan.go`** - Integrated progress reporting
- **`cmd/aftersec/cmd/malware_scan_volume.go`** - Integrated progress reporting

## Usage

### Enable Progress Reporting

```bash
# Single file scan with progress
aftersec malware-scan /path/to/file --progress

# Directory scan with progress
aftersec malware-scan -r /path/to/folder --progress

# Volume scan with progress
aftersec scan-volume /Volumes/External --progress
```

### Event Types

Progress events are emitted as JSON to **stderr** (stdout is reserved for normal output):

#### 1. `scan_start`
Emitted when a scan begins
```json
{
  "type": "scan_start",
  "timestamp": "2026-03-28T14:32:00Z",
  "data": {
    "path": "/path/to/scan",
    "total_files": 1250
  }
}
```

#### 2. `file_scanning`
Emitted when starting to scan a file
```json
{
  "type": "file_scanning",
  "timestamp": "2026-03-28T14:32:01Z",
  "data": {
    "file": "/path/to/file.exe",
    "progress": {
      "scanned": 10,
      "total": 1250,
      "percentage": 0.8,
      "threats": 0,
      "elapsed": 2.5,
      "eta": 310.5,
      "rate": 4.0
    }
  }
}
```

#### 3. `file_scanned`
Emitted when a file scan completes
```json
{
  "type": "file_scanned",
  "timestamp": "2026-03-28T14:32:02Z",
  "data": {
    "file": "/path/to/file.exe",
    "infected": true,
    "progress": {
      "scanned": 11,
      "total": 1250,
      "percentage": 0.88,
      "threats": 1,
      "elapsed": 2.7,
      "eta": 304.3,
      "rate": 4.07
    },
    "threats": [
      {
        "name": "Trojan.Generic.12345",
        "severity": "high",
        "description": "Generic trojan detected",
        "engine": "clamav"
      }
    ]
  }
}
```

#### 4. `threat_detected`
Emitted immediately when a threat is found (for real-time alerts)
```json
{
  "type": "threat_detected",
  "timestamp": "2026-03-28T14:32:02Z",
  "data": {
    "file": "/path/to/malware.exe",
    "threats": [
      {
        "name": "Win32.Malware.Generic",
        "severity": "critical",
        "description": "Malicious executable detected",
        "engine": "yara"
      }
    ]
  }
}
```

#### 5. `scan_complete`
Emitted when the entire scan finishes
```json
{
  "type": "scan_complete",
  "timestamp": "2026-03-28T14:37:15Z",
  "data": {
    "total_scanned": 1250,
    "threats_found": 3,
    "duration": 315.2,
    "clean_files": 1247
  }
}
```

#### 6. `scan_error`
Emitted when an error occurs during scanning
```json
{
  "type": "scan_error",
  "timestamp": "2026-03-28T14:32:05Z",
  "data": {
    "file": "/path/to/locked.file",
    "error": "permission denied"
  }
}
```

#### 7. `progress_update`
Can be emitted periodically for manual progress updates
```json
{
  "type": "progress_update",
  "timestamp": "2026-03-28T14:35:00Z",
  "data": {
    "progress": {
      "scanned": 625,
      "total": 1250,
      "percentage": 50.0,
      "threats": 2,
      "elapsed": 150.0,
      "eta": 150.0,
      "rate": 4.17
    }
  }
}
```

## Progress Metrics

Each progress object contains:

| Field | Type | Description |
|-------|------|-------------|
| `scanned` | int | Number of files scanned so far |
| `total` | int | Total number of files to scan |
| `percentage` | float | Completion percentage (0-100) |
| `threats` | int | Number of threats found so far |
| `elapsed` | float | Seconds elapsed since scan start |
| `eta` | float | Estimated seconds remaining |
| `rate` | float | Files scanned per second |

## GUI Integration Example

### Python GUI Example

```python
import subprocess
import json
import sys

def scan_with_progress(path):
    process = subprocess.Popen(
        ['aftersec', 'malware-scan', path, '--progress'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Read progress events from stderr
    for line in process.stderr:
        try:
            event = json.loads(line)
            handle_progress_event(event)
        except json.JSONDecodeError:
            continue

    # Read final output from stdout
    output = process.stdout.read()
    return output

def handle_progress_event(event):
    event_type = event['type']
    data = event['data']

    if event_type == 'scan_start':
        print(f"Starting scan of {data['path']}")
        print(f"Total files: {data['total_files']}")

    elif event_type == 'file_scanning':
        progress = data['progress']
        print(f"Scanning: {data['file']}")
        print(f"Progress: {progress['percentage']:.1f}% ({progress['scanned']}/{progress['total']})")
        print(f"ETA: {progress['eta']:.0f}s | Rate: {progress['rate']:.1f} files/s")

    elif event_type == 'threat_detected':
        print(f"⚠️  THREAT FOUND: {data['file']}")
        for threat in data['threats']:
            print(f"  - {threat['name']} ({threat['severity']})")

    elif event_type == 'scan_complete':
        print(f"✅ Scan complete!")
        print(f"  Scanned: {data['total_scanned']} files")
        print(f"  Threats: {data['threats_found']}")
        print(f"  Duration: {data['duration']:.1f}s")

# Usage
scan_with_progress('/path/to/scan')
```

### Electron/Node.js GUI Example

```javascript
const { spawn } = require('child_process');

function scanWithProgress(path, callbacks) {
  const scanner = spawn('aftersec', ['malware-scan', path, '--progress']);

  // Listen for progress events on stderr
  scanner.stderr.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach(line => {
      if (!line.trim()) return;

      try {
        const event = JSON.parse(line);
        handleProgressEvent(event, callbacks);
      } catch (e) {
        console.error('Failed to parse progress event:', line);
      }
    });
  });

  // Listen for final output on stdout
  scanner.stdout.on('data', (data) => {
    console.log('Scanner output:', data.toString());
  });

  scanner.on('close', (code) => {
    console.log(`Scanner exited with code ${code}`);
  });
}

function handleProgressEvent(event, callbacks) {
  switch (event.type) {
    case 'scan_start':
      callbacks.onStart?.(event.data);
      break;
    case 'file_scanning':
      callbacks.onFileScanning?.(event.data);
      break;
    case 'file_scanned':
      callbacks.onFileScanned?.(event.data);
      break;
    case 'threat_detected':
      callbacks.onThreatDetected?.(event.data);
      break;
    case 'scan_complete':
      callbacks.onComplete?.(event.data);
      break;
    case 'scan_error':
      callbacks.onError?.(event.data);
      break;
  }
}

// Usage
scanWithProgress('/path/to/scan', {
  onStart: (data) => {
    console.log(`Starting scan of ${data.path}`);
    console.log(`Total files: ${data.total_files}`);
  },
  onFileScanning: (data) => {
    const p = data.progress;
    console.log(`Scanning: ${data.file}`);
    console.log(`Progress: ${p.percentage.toFixed(1)}% (${p.scanned}/${p.total})`);
  },
  onThreatDetected: (data) => {
    console.log(`⚠️  THREAT: ${data.file}`);
    data.threats.forEach(t => {
      console.log(`  - ${t.name} (${t.severity})`);
    });
  },
  onComplete: (data) => {
    console.log(`✅ Scan complete!`);
    console.log(`  Threats: ${data.threats_found}/${data.total_scanned}`);
  }
});
```

### Go/Fyne GUI Example

```go
package main

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
)

type ProgressEvent struct {
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

func scanWithProgress(path string, progressBar *widget.ProgressBar, statusLabel *widget.Label) {
	cmd := exec.Command("aftersec", "malware-scan", path, "--progress")

	stderr, _ := cmd.StderrPipe()
	cmd.Start()

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		var event ProgressEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		switch event.Type {
		case "file_scanning":
			if progress, ok := event.Data["progress"].(map[string]interface{}); ok {
				percentage := progress["percentage"].(float64)
				progressBar.SetValue(percentage / 100.0)

				file := event.Data["file"].(string)
				statusLabel.SetText(fmt.Sprintf("Scanning: %s", file))
			}

		case "threat_detected":
			// Show threat alert
			file := event.Data["file"].(string)
			statusLabel.SetText(fmt.Sprintf("⚠️  Threat found in: %s", file))

		case "scan_complete":
			totalScanned := event.Data["total_scanned"].(float64)
			threatsFound := event.Data["threats_found"].(float64)
			statusLabel.SetText(fmt.Sprintf("✅ Complete: %d threats in %d files",
				int(threatsFound), int(totalScanned)))
		}
	}

	cmd.Wait()
}
```

## Benefits

1. **Real-time Feedback**: Users see scan progress immediately
2. **Accurate ETAs**: Calculate remaining time based on actual scan rate
3. **Immediate Threat Alerts**: Get notified as soon as threats are detected
4. **Non-blocking UI**: GUI remains responsive during scans
5. **Detailed Metrics**: Track scan rate, elapsed time, and more
6. **Error Handling**: Receive error events for failed file scans

## Implementation Details

### ProgressReporter API

```go
// Create reporter
progress := darkscan.NewProgressReporter(enabled bool)

// Emit events
progress.ScanStart(path string, totalFiles int)
progress.FileScanning(path string)
progress.FileScanned(result *ScanResult)
progress.ThreatDetected(result *ScanResult)
progress.ScanComplete(totalScanned, threatsFound int, duration time.Duration)
progress.Error(path string, err error)
progress.UpdateProgress(scanned, total, threats int)
```

### Event Emission

All events are emitted to **stderr** as JSON-encoded strings, one per line:
- Stdout is reserved for normal command output
- Stderr carries progress events for GUI consumption
- Each event is a complete JSON object on a single line
- Invalid JSON lines should be ignored

### Thread Safety

The ProgressReporter is safe for concurrent use:
- All methods are thread-safe
- Can be called from multiple goroutines
- Progress metrics are atomic where necessary

## Future Enhancements

- [ ] Add `progress_interval` flag to control event frequency
- [ ] Add file size metrics to progress data
- [ ] Add engine-specific progress tracking
- [ ] Support websocket progress streaming
- [ ] Add binary protocol option for lower overhead
- [ ] Include hash computation progress

## See Also

- DarkScan CLI Progress Implementation: `/Users/ryan/development/darkscancli/cmd/darkscan/progress.go`
- AfterSec Progress Module: `pkg/darkscan/progress.go`
- Malware Scanner: `cmd/aftersec/cmd/malware_scan.go`
- Volume Scanner: `cmd/aftersec/cmd/malware_scan_volume.go`
