# AfterSec

A MacOS Security Posture Manager. AfterSec provides an intuitive GUI and a powerful CLI to scan, monitor, and manage your Mac's security settings (e.g., SIP, Firewall, Gatekeeper, SSH Auth).

## Features

- **Security Posture Review**: Assess macOS system capabilities, network security settings, filesystem permissions, and system defaults.
- **Diff & Commit**: Baseline your system's current security state and review exactly what settings have changed over time.
- **Revision History**: Maintain a full audit log of system states for tracking drifts.
- **Customizable Settings**: Set your preferred strictness level, define ignored paths via a whitelist, and configure auto-scans natively in the UI.
- **GUI & CLI Integration**: Run with a beautifully native Fyne desktop interface or use the structured text-based CLI.

## Building the Project

Use the included build script to quickly compile the binaries:

```bash
./build.sh both  # Compiles both CLI and GUI to ./bin/
./build.sh gui   # Compiles only the GUI
./build.sh cli   # Compiles only the CLI
./build.sh clean # Cleans the bin directory
```

## Usage

### Graphical Interface (GUI)

Launch the graphical application to interact visually with the scanning and diffing tools:

```bash
./bin/aftersec-gui
```

- **Scanner Tab**: Scan your macOS device in real-time, observing progress visually.
- **Diff & Commit Tab**: Spot drifts from your last baseline commit across specific metric fields.
- **History Tab**: Access previous configuration snapshots.
- **Settings Tab**: Toggle rigorous auditing (Strict Mode), manage auto-runs, and declare whitelists.

### Command Line Interface (CLI)

The CLI provides a structured, terminal-friendly interface for headless operations:

```bash
./bin/aftersec scan    # Perform a system security scan
./bin/aftersec diff    # Compare current state with your latest commit
./bin/aftersec commit  # Establish a new baseline
./bin/aftersec history # List all previous baseline commits
```

## Storage & Configuration

All configuration settings and historical baseline commits automatically persist within the `~/.aftersec/` directory.
