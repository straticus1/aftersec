# AfterSec Load Testing

Comprehensive load testing suite for the AfterSec API.

## Quick Start

### 1. Get a JWT Token

```bash
# Login to get JWT token
curl -X POST https://api.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  | jq -r '.token'
```

### 2. Run Basic Load Test

```bash
# Set JWT token
export JWT_TOKEN="your-jwt-token-here"

# Run load test (10 concurrent users, 30 seconds)
go run loadtest.go \
  -url https://localhost:8080 \
  -token $JWT_TOKEN \
  -c 10 \
  -d 30s \
  -skip-tls
```

### 3. View Results

```
====================================================================================
  LOAD TEST RESULTS
====================================================================================

Total Requests:      2847
Successful:          2845 (99.93%)
Failed:              2 (0.07%)
Total Data:          15.43 MB

Throughput:
  Requests/sec:      94.90
  Bytes/sec:         527.31 KB/s

Latency:
  Min:               12.456ms
  Max:               543.221ms
  Avg:               102.334ms
  P50 (median):      95.123ms
  P95:               187.456ms
  P99:               298.765ms

Assessment:
  ⚠️  FAIR - System handles 100-500 req/s
  ✅ LOW LATENCY - P95 < 100ms
  ✅ EXCELLENT RELIABILITY - >99.9% success

====================================================================================
```

## Available Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-url` | `https://localhost:8080` | Base URL of API server |
| `-token` | (required) | JWT authentication token |
| `-c` | `10` | Number of concurrent workers |
| `-d` | `30s` | Test duration (e.g., 30s, 5m, 1h) |
| `-r` | `5s` | Ramp-up time for workers |
| `-rps` | `0` | Target requests/sec (0 = unlimited) |
| `-skip-tls` | `true` | Skip TLS certificate verification |
| `-timeout` | `30s` | Request timeout |
| `-scenario` | (empty) | Run specific scenario (empty = all) |

## Test Scenarios

The load tester includes these built-in scenarios:

1. **Health Check** (10% weight)
   - Endpoint: `GET /api/v1/health`
   - Expected: 100% success, <10ms latency

2. **List Organizations** (20% weight)
   - Endpoint: `GET /api/v1/organizations`
   - Expected: 99.9% success, <100ms latency

3. **List Endpoints** (30% weight)
   - Endpoint: `GET /api/v1/endpoints`
   - Expected: 99.9% success, <100ms latency

4. **List Scans** (25% weight)
   - Endpoint: `GET /api/v1/scans`
   - Expected: 99.9% success, <200ms latency

5. **Bandit Query** (5% weight)
   - Endpoint: `POST /api/v1/bandit/query`
   - Expected: 95% success, 2-5s latency (LLM processing)

6. **Dark Web Alerts** (10% weight)
   - Endpoint: `GET /api/v1/darkweb/alerts`
   - Expected: 99% success, <500ms latency

## Example Tests

### Production Readiness Test

```bash
# 100 concurrent users, 10 minutes, 1000 req/s target
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 100 \
  -d 10m \
  -rps 1000 \
  -skip-tls=false
```

### Spike Test

```bash
# Rapidly increase load to 500 concurrent users
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 500 \
  -d 2m \
  -r 30s
```

### AI Endpoint Test

```bash
# Test LLM budget controls and circuit breakers
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -scenario "Bandit Query" \
  -c 10 \
  -d 5m \
  -rps 50
```

### Endurance Test

```bash
# 4-hour test to detect memory leaks
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 100 \
  -d 4h \
  -rps 500
```

## Performance Targets

Based on architecture (3 API servers, PostgreSQL + Redis, 10K endpoints):

| Scenario | Target RPS | P95 Latency | Success Rate |
|----------|------------|-------------|--------------|
| Health Check | >5000 | <10ms | >99.99% |
| Read Operations | >1000 | <200ms | >99.9% |
| Write Operations | >500 | <500ms | >99.5% |
| AI Operations | >50 | 2-5s | >95% |
| Mixed Workload | >800 | <300ms | >99.5% |

## Troubleshooting

### Issue: "JWT token is required"

```bash
# Make sure JWT_TOKEN is set
echo $JWT_TOKEN

# If empty, get a new token
export JWT_TOKEN="your-token-here"
```

### Issue: "connection refused"

```bash
# Check if API server is running
curl https://localhost:8080/api/v1/health

# Check Docker services
docker-compose -f docker-compose.production.yml ps
```

### Issue: High error rate

```bash
# Check API server logs
docker-compose -f docker-compose.production.yml logs api-server

# Check rate limiting
docker exec aftersec-redis redis-cli INFO stats
```

### Issue: "x509: certificate signed by unknown authority"

```bash
# Use -skip-tls flag for self-signed certificates
go run loadtest.go -skip-tls=true ...

# Or install certificates in system trust store
```

## Files

- `loadtest.go` - Main load testing tool
- `LOAD_TESTING_GUIDE.md` - Comprehensive testing guide
- `README.md` - This file

## Requirements

- Go 1.21 or higher
- Valid JWT authentication token
- Access to AfterSec API (local or remote)

## License

Copyright (c) 2026 After Dark Systems, LLC
