# AfterSec Load Testing Guide

Complete guide for load testing the AfterSec API under production conditions.

## Prerequisites

### Required Tools
- Go 1.21+
- JWT authentication token
- Access to AfterSec API (local or production)

### Optional Tools
- `hey` (HTTP load generator): `go install github.com/rakyll/hey@latest`
- `vegeta` (HTTP load tester): `go install github.com/tsenart/vegeta@latest`
- Grafana for real-time monitoring

## Quick Start

### Basic Load Test (10 concurrent users, 30 seconds)

```bash
cd tests/load

# Get JWT token (replace with your credentials)
export JWT_TOKEN="your-jwt-token-here"

# Run basic load test
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 10 \
  -d 30s \
  -skip-tls
```

### Production Scenario (100 concurrent users, 5 minutes)

```bash
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 100 \
  -d 5m \
  -r 30s \
  -rps 500
```

## Test Scenarios

### 1. Health Check Test

Tests basic infrastructure responsiveness.

```bash
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -scenario "Health Check" \
  -c 50 \
  -d 1m
```

**Expected Results:**
- ✅ >5000 req/s
- ✅ P95 latency <10ms
- ✅ 100% success rate

### 2. Read-Heavy Workload

Simulates dashboard usage (90% reads, 10% writes).

```bash
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 100 \
  -d 5m \
  -rps 1000
```

**Scenarios Tested:**
- 30%: List Endpoints
- 25%: List Scans
- 20%: List Organizations
- 15%: Dark Web Alerts
- 10%: Bandit Query (AI-heavy)

**Expected Results:**
- ✅ >800 req/s sustained
- ✅ P95 latency <200ms
- ✅ >99% success rate

### 3. AI-Heavy Workload

Tests LLM budget controls and circuit breakers.

```bash
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -scenario "Bandit Query" \
  -c 10 \
  -d 2m \
  -rps 50
```

**Expected Results:**
- ✅ 50 req/s (rate limited by LLM APIs)
- ⚠️  P95 latency 2-5s (LLM processing time)
- ✅ Circuit breaker activates if LLM fails
- ✅ Budget limits enforced

### 4. Database Stress Test

Tests PgBouncer connection pooling.

```bash
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 200 \
  -d 10m \
  -rps 2000
```

**Expected Results:**
- ✅ >1500 req/s sustained
- ✅ PgBouncer handles connection pooling
- ✅ No connection pool exhaustion
- ✅ P95 latency <500ms

### 5. Spike Test

Tests auto-scaling and rate limiting.

```bash
# Gradual ramp-up
for conc in 10 50 100 200 500; do
  echo "Testing with $conc concurrent users..."
  go run loadtest.go \
    -url https://api.yourdomain.com \
    -token $JWT_TOKEN \
    -c $conc \
    -d 30s \
    -skip-tls
  sleep 10
done
```

**Expected Results:**
- ✅ Graceful degradation under load
- ✅ Rate limiting activates at high concurrency
- ✅ No cascading failures
- ⚠️  Latency increases linearly with load

### 6. Endurance Test

Tests for memory leaks and resource exhaustion.

```bash
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 100 \
  -d 4h \
  -rps 500
```

**Monitor:**
- Memory usage (should be stable)
- Connection pool utilization
- Goroutine count
- Database connection count

**Expected Results:**
- ✅ No memory leaks over 4 hours
- ✅ Stable performance throughout test
- ✅ Resource cleanup after test

## Production Benchmarks

### Target Metrics (10,000 Endpoints)

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| **Throughput** |
| Total Requests/sec | >1000 | TBD | 🔄 |
| Read Requests/sec | >800 | TBD | 🔄 |
| Write Requests/sec | >200 | TBD | 🔄 |
| **Latency** |
| P50 (median) | <50ms | TBD | 🔄 |
| P95 | <200ms | TBD | 🔄 |
| P99 | <500ms | TBD | 🔄 |
| Max | <2s | TBD | 🔄 |
| **Reliability** |
| Success Rate | >99.9% | TBD | 🔄 |
| Uptime | >99.99% | TBD | 🔄 |
| **Resources** |
| CPU Usage (avg) | <60% | TBD | 🔄 |
| Memory Usage | <80% | TBD | 🔄 |
| DB Connections | <100 | TBD | 🔄 |
| **Cost** |
| LLM API Cost/1000 req | <$0.10 | TBD | 🔄 |

## Monitoring During Tests

### Grafana Dashboards

```bash
# Access Grafana
open https://grafana.yourdomain.com

# Watch these metrics:
# 1. API Request Rate (req/s)
# 2. Response Time (P50, P95, P99)
# 3. Error Rate
# 4. CPU/Memory Usage
# 5. Database Connection Pool
# 6. Redis Cache Hit Rate
# 7. LLM API Budget
```

### Prometheus Queries

```promql
# Request rate
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])

# P95 latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Database connections
pg_stat_activity_count

# Redis cache hit rate
redis_keyspace_hits_total / (redis_keyspace_hits_total + redis_keyspace_misses_total)
```

## Interpreting Results

### Success Criteria

| Category | Metric | Good | Warning | Critical |
|----------|--------|------|---------|----------|
| **Throughput** | req/s | >1000 | 500-1000 | <500 |
| **Latency** | P95 | <100ms | 100-500ms | >500ms |
| **Reliability** | Success % | >99.9% | 99-99.9% | <99% |
| **CPU** | Usage % | <60% | 60-80% | >80% |
| **Memory** | Usage % | <70% | 70-85% | >85% |

### Common Issues and Solutions

#### Issue: High Latency (P95 >500ms)

**Diagnosis:**
```bash
# Check database slow queries
docker exec aftersec-postgres-primary psql -U aftersec -c \
  "SELECT query, mean_exec_time, calls FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"

# Check Redis cache hit rate
docker exec aftersec-redis redis-cli info stats | grep hits
```

**Solutions:**
- Add database indexes
- Increase Redis memory
- Enable query result caching
- Optimize N+1 queries

#### Issue: Low Throughput (<500 req/s)

**Diagnosis:**
```bash
# Check connection pool saturation
docker exec aftersec-pgbouncer psql -p 6432 -U aftersec pgbouncer -c "SHOW POOLS;"

# Check goroutine count
curl http://localhost:8080/debug/pprof/goroutine?debug=1
```

**Solutions:**
- Increase PgBouncer pool size
- Scale API servers horizontally
- Add read replicas
- Implement connection pooling

#### Issue: High Error Rate (>1%)

**Diagnosis:**
```bash
# Check error logs
docker-compose -f docker-compose.production.yml logs api-server | grep ERROR

# Check circuit breaker status
curl -H "Authorization: Bearer $JWT_TOKEN" \
  https://api.yourdomain.com/api/v1/ai/circuit-breaker/status
```

**Solutions:**
- Fix application errors
- Increase timeout values
- Add retry logic
- Fix circuit breaker thresholds

## Advanced Load Testing

### Using `hey` (Alternative Tool)

```bash
# Install hey
go install github.com/rakyll/hey@latest

# Basic load test
hey -n 10000 -c 100 -m GET \
  -H "Authorization: Bearer $JWT_TOKEN" \
  https://api.yourdomain.com/api/v1/health

# POST request test
echo '{"query":"What processes are running?"}' | \
  hey -n 1000 -c 10 -m POST \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -D /dev/stdin \
  https://api.yourdomain.com/api/v1/bandit/query
```

### Using `vegeta` (Alternative Tool)

```bash
# Install vegeta
go install github.com/tsenart/vegeta@latest

# Create targets file
cat > targets.txt <<EOF
GET https://api.yourdomain.com/api/v1/health
Authorization: Bearer $JWT_TOKEN

GET https://api.yourdomain.com/api/v1/organizations
Authorization: Bearer $JWT_TOKEN

GET https://api.yourdomain.com/api/v1/endpoints
Authorization: Bearer $JWT_TOKEN
EOF

# Run attack
cat targets.txt | vegeta attack -duration=60s -rate=100 | \
  vegeta report -type=text

# Generate HTML report
cat targets.txt | vegeta attack -duration=60s -rate=100 | \
  vegeta plot > report.html
```

## Pre-Production Checklist

Before running production load tests:

### Infrastructure
- [ ] Docker Compose services are running
- [ ] PostgreSQL primary and replica are healthy
- [ ] Redis is running with persistence
- [ ] PgBouncer is configured (pool size 100)
- [ ] Prometheus/Grafana are monitoring
- [ ] Cloudflare Tunnel is active

### Configuration
- [ ] JWT secret is set
- [ ] LLM budget limits are configured ($100/day, $2000/month)
- [ ] Rate limiting is enabled (Redis-based)
- [ ] Circuit breakers are initialized
- [ ] Database connection pool: 100 max connections

### Security
- [ ] TLS certificates are valid
- [ ] API authentication is enforced
- [ ] Rate limiting is active
- [ ] SQL injection audit passed
- [ ] Input validation is enabled

### Monitoring
- [ ] Grafana dashboards are configured
- [ ] Alerts are set up for critical metrics
- [ ] Log aggregation is working (Loki)
- [ ] Error tracking is enabled

## Post-Test Analysis

### Generate Report

```bash
# Run comprehensive test
go run loadtest.go \
  -url https://api.yourdomain.com \
  -token $JWT_TOKEN \
  -c 100 \
  -d 10m \
  -rps 1000 \
  > loadtest_report.txt 2>&1

# Analyze Prometheus metrics
curl http://localhost:9090/api/v1/query \
  -d 'query=rate(http_requests_total[10m])' | jq .

# Export Grafana dashboard
curl -H "Authorization: Bearer $GRAFANA_TOKEN" \
  http://localhost:3000/api/dashboards/uid/aftersec-api \
  > grafana_snapshot.json
```

### Document Results

Create `LOAD_TEST_RESULTS.md`:

```markdown
# Load Test Results - [Date]

## Configuration
- Concurrency: 100 workers
- Duration: 10 minutes
- Rate Limit: 1000 req/s
- Test Scenarios: All (weighted)

## Results
- Total Requests: [Number]
- Success Rate: [Percentage]
- Throughput: [req/s]
- P95 Latency: [ms]

## Issues Found
- [List any issues discovered]

## Recommendations
- [List optimization recommendations]
```

## Continuous Load Testing

### Automated Testing

```bash
# Add to CI/CD pipeline
# .github/workflows/load-test.yml

name: Load Test
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
      - name: Run Load Test
        run: |
          cd tests/load
          go run loadtest.go \
            -url ${{ secrets.API_URL }} \
            -token ${{ secrets.JWT_TOKEN }} \
            -c 50 \
            -d 5m \
            > results.txt
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: load-test-results
          path: tests/load/results.txt
```

## Support

For questions or issues:
- GitHub Issues: https://github.com/your-org/aftersec/issues
- Slack: #aftersec-performance
- Email: devops@aftersec.io
