# ClamAV Definition Mirror Server

## Overview

AfterSec Management Server can act as a centralized ClamAV definition mirror, automatically downloading and distributing virus definitions to all enrolled endpoints.

## Benefits

- **Bandwidth Optimization**: One server downloads, all endpoints pull from local network
- **Air-Gapped Networks**: Works in isolated environments without internet access
- **Version Control**: Track definition versions across your fleet
- **Centralized Management**: Control when and how endpoints update
- **Faster Updates**: Local network speeds instead of internet
- **Compliance**: Complete audit trail of definition versions

## Server Configuration

### Enable ClamAV Updater

Set environment variables when starting aftersec-server:

```bash
# Enable the ClamAV definition updater
export CLAMAV_UPDATER_ENABLED=true

# Optional: Custom storage path (default: /var/aftersec/clamav-defs)
export CLAMAV_STORAGE_PATH=/var/aftersec/clamav-defs

# Start the server
./bin/aftersec-server
```

### Docker Compose Example

```yaml
services:
  aftersec-server:
    image: aftersec/management-server:latest
    environment:
      - CLAMAV_UPDATER_ENABLED=true
      - CLAMAV_STORAGE_PATH=/data/clamav-defs
      - DATABASE_URL=postgres://postgres:postgres@db:5432/aftersec
    volumes:
      - clamav-defs:/data/clamav-defs
    ports:
      - "8080:8080"
      - "9090:9090"

volumes:
  clamav-defs:
```

### What Happens on Server Startup

1. **Initialization**: Creates storage directory at configured path
2. **Initial Update**: Runs `freshclam` to download latest definitions (~300MB)
3. **Background Updates**: Automatically updates every 4 hours
4. **REST API**: Exposes endpoints for clients to download definitions

## REST API Endpoints

### Public Endpoints (No Authentication Required)

#### Get Definition Version
```bash
GET /api/v1/clamav/definitions/version

# Response:
{
  "version": "1711478400",
  "main_version": "63",
  "daily_version": "27642",
  "bytecode_version": "334",
  "updated_at": "2026-03-26T21:00:00Z",
  "total_size_bytes": 298467328,
  "total_size_mb": 284.6,
  "definition_count": 3,
  "freshclam_version": "ClamAV 1.0.0/26873/..."
}
```

#### Download Latest Bundle (All Definitions)
```bash
GET /api/v1/clamav/definitions/latest

# Downloads: clamav-definitions.tar.gz
# Contains: main.cvd, daily.cvd, bytecode.cvd, metadata.json
```

#### Download Specific File
```bash
GET /api/v1/clamav/definitions/main.cvd
GET /api/v1/clamav/definitions/daily.cvd
GET /api/v1/clamav/definitions/bytecode.cvd
```

#### List Available Definitions
```bash
GET /api/v1/clamav/definitions/list

# Response:
{
  "files": [
    {
      "name": "main.cvd",
      "size_bytes": 156237824,
      "size_mb": 149.0,
      "mod_time": "2026-03-26T21:00:00Z"
    },
    ...
  ],
  "count": 3
}
```

### Admin Endpoints (Authentication Required)

#### Force Update
```bash
POST /api/v1/clamav/update
Authorization: Bearer <jwt-token>

# Response:
{
  "success": true,
  "message": "Definitions updated successfully",
  "metadata": { ... }
}
```

## Client Configuration

### Configure Endpoints to Use Mirror

Edit `~/.aftersec/config.yaml` on client endpoints:

```yaml
daemon:
  darkscan:
    enabled: true
    use_cli: true
    cli_binary_path: darkscan
    engines:
      clamav:
        enabled: true
        database_path: /usr/local/share/clamav
        auto_update: false  # Disable auto freshclam
        mirror_url: https://aftersec-server.company.com:8080
```

### Manual Update from Mirror

```bash
# Download latest definitions from your mirror
curl -o clamav-defs.tar.gz https://aftersec-server:8080/api/v1/clamav/definitions/latest

# Extract to ClamAV database directory
sudo tar -xzf clamav-defs.tar.gz -C /usr/local/share/clamav/

# Verify
darkscan scan /path/to/file
```

### Programmatic Update (Go)

```go
import "aftersec/pkg/darkscan"

// Update from mirror
err := darkscan.UpdateFromMirror(
    "https://aftersec-server:8080",
    "/usr/local/share/clamav",
)
if err != nil {
    log.Fatalf("Update failed: %v", err)
}
```

## Storage Requirements

### Server-Side

- **Storage**: ~300-400 MB for definition files
- **Memory**: ~100 MB for updater process
- **Network**: ~300 MB download every 4 hours (or less frequently)

### Client-Side

- **Storage**: ~300-400 MB for definition files (same as server)
- **Network**: One-time download from local server (much faster)

## Monitoring

### Check Server Status

```bash
# Get current version
curl https://aftersec-server:8080/api/v1/clamav/definitions/version | jq

# List all definitions
curl https://aftersec-server:8080/api/v1/clamav/definitions/list | jq
```

### Server Logs

```
[ClamAV Updater] Starting ClamAV definition updater (interval: 4h0m0s)
[ClamAV Updater] Storage path: /var/aftersec/clamav-defs
[ClamAV Updater] Freshclam path: /usr/local/bin/freshclam
[ClamAV Updater] Running ClamAV definition update...
[ClamAV Updater] Update completed in 45.2s
[ClamAV Updater] Metadata updated: 3 definitions, 284.6 MB total
```

## Architecture

```
┌─────────────────────────────────────────┐
│    AfterSec Management Server           │
│                                          │
│  ┌──────────────────────────────────┐   │
│  │  ClamAV Updater Service          │   │
│  │  - Runs freshclam every 4h       │   │
│  │  - Stores in /var/aftersec/...   │   │
│  └──────────────────────────────────┘   │
│                ↓                         │
│  ┌──────────────────────────────────┐   │
│  │  REST API Endpoints              │   │
│  │  /api/v1/clamav/definitions/*    │   │
│  └──────────────────────────────────┘   │
└────────────────┬────────────────────────┘
                 │
        ┌────────┴─────────┐
        ↓                  ↓
┌──────────────┐    ┌──────────────┐
│  Endpoint 1  │    │  Endpoint 2  │
│              │    │              │
│  darkscan    │    │  darkscan    │
│  (ClamAV)    │    │  (ClamAV)    │
└──────────────┘    └──────────────┘
```

## Troubleshooting

### Server: Updater Not Starting

Check logs for initialization errors:
```bash
# Ensure freshclam is installed
which freshclam

# Check storage directory permissions
ls -la /var/aftersec/clamav-defs/

# Verify environment variable
echo $CLAMAV_UPDATER_ENABLED
```

### Server: Update Fails

```bash
# Test freshclam manually
freshclam --datadir=/var/aftersec/clamav-defs --verbose

# Check internet connectivity
ping database.clamav.net
```

### Client: Cannot Download from Mirror

```bash
# Test connectivity
curl https://aftersec-server:8080/api/v1/clamav/definitions/version

# Check TLS/SSL if using HTTPS
curl -k https://aftersec-server:8080/api/v1/clamav/definitions/version
```

## Security Considerations

1. **Definition Integrity**: Definitions are downloaded directly from ClamAV's official servers by the mirror
2. **Transport Security**: Use HTTPS for the mirror server in production
3. **Access Control**: Public endpoints allow unauthenticated access (intentional for endpoint updates)
4. **Network Segmentation**: Mirror server should be accessible from all endpoints

## Future Enhancements

- [ ] Support for YARA rule distribution
- [ ] Bandwidth throttling for large deployments
- [ ] Definition version pinning/rollback
- [ ] CDN integration for geo-distributed deployments
- [ ] Delta updates (only download changed files)
- [ ] Webhook notifications on new definitions
- [ ] Integration with enterprise patch management systems
