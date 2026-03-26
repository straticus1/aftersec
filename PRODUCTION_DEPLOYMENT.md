# AfterSec Production Deployment Guide

This guide covers deploying AfterSec to production on OCI (Oracle Cloud Infrastructure) with Cloudflare Tunnels, self-hosted databases, and comprehensive monitoring.

## Architecture Overview

- **Infrastructure**: OCI Compute instances (self-hosted)
- **CDN/Security**: Cloudflare (Tunnels, WAF, DDoS protection)
- **Database**: PostgreSQL with streaming replication (primary + replica)
- **Caching**: Redis with persistence
- **API Servers**: 3 replicas with auto-scaling
- **Monitoring**: Prometheus + Grafana + Loki
- **Estimated Cost**: $2,340/month for 10,000 endpoints

## Prerequisites

### OCI Resources
- 3x VM.Standard.E4.Flex instances (4 vCPU, 64GB RAM each)
- OCI Object Storage bucket for backups
- OCI Load Balancer
- Security Lists configured for ports: 80, 443, 8080, 9090

### External Services
- Cloudflare account with Tunnels configured
- DarkAPI.io account ($199/month)
- LLM API keys (OpenAI, Anthropic, Google)

### Required Tools
- Docker & Docker Compose
- cloudflared (Cloudflare Tunnel daemon)
- PostgreSQL client tools
- Git

## Step 1: Server Preparation

### OCI Compute Instance Setup

```bash
# Update system
sudo yum update -y

# Install Docker
sudo yum install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Cloudflare Tunnel
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
sudo mv cloudflared /usr/local/bin/
sudo chmod +x /usr/local/bin/cloudflared

# Clone AfterSec repository
git clone https://github.com/your-org/aftersec.git
cd aftersec
```

## Step 2: Environment Configuration

```bash
# Copy example environment file
cp .env.production.example .env

# Generate strong JWT secret
openssl rand -base64 64 > jwt_secret.txt

# Edit .env file
nano .env
```

### Required Environment Variables

Fill in all values in `.env`:

1. **Database**: Set `POSTGRES_PASSWORD` to a strong password
2. **JWT**: Set `JWT_SECRET` from jwt_secret.txt
3. **LLM APIs**: Add your OpenAI, Anthropic, and Gemini API keys
4. **DarkAPI**: Add your DarkAPI.io API key
5. **OCI**: Configure OCI namespace, bucket, and region
6. **Monitoring**: Set `GRAFANA_PASSWORD`
7. **Domain**: Set your domain name

## Step 3: TLS Certificates

### Generate Self-Signed Certificates (Development)

```bash
mkdir -p certs

# Generate CA
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
  -subj "/C=US/ST=CA/L=SF/O=AfterSec/CN=AfterSec CA"

# Generate server certificate
openssl genrsa -out certs/server.key 4096
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/C=US/ST=CA/L=SF/O=AfterSec/CN=api.yourdomain.com"
openssl x509 -req -days 365 -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt

chmod 600 certs/*.key
```

### Production: Use Let's Encrypt

```bash
# Install certbot
sudo yum install -y certbot

# Get certificates
sudo certbot certonly --standalone -d api.yourdomain.com \
  -d grpc.yourdomain.com -d dashboard.yourdomain.com

# Copy to certs directory
sudo cp /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem certs/server.crt
sudo cp /etc/letsencrypt/live/api.yourdomain.com/privkey.pem certs/server.key
```

## Step 4: Database Initialization

Create `scripts/postgres-init.sql`:

```sql
-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS aftersec;

-- Row-level security for multi-tenancy
ALTER TABLE IF EXISTS aftersec.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS aftersec.endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS aftersec.organizations ENABLE ROW LEVEL SECURITY;

-- Create indexes for performance
-- (Add your table schemas and indexes here)
```

## Step 5: Cloudflare Tunnel Configuration

```bash
# Login to Cloudflare
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create aftersec-production

# Create tunnel configuration
cat > ~/.cloudflared/config.yml <<EOF
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: api.yourdomain.com
    service: http://localhost:8080
  - hostname: grpc.yourdomain.com
    service: http://localhost:9090
  - hostname: dashboard.yourdomain.com
    service: http://localhost:3000
  - hostname: grafana.yourdomain.com
    service: http://localhost:3000
  - service: http_status:404
EOF

# Run tunnel
cloudflared tunnel run aftersec-production
```

### Install as systemd service

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

## Step 6: Deploy Services

```bash
# Build Docker images
docker-compose -f docker-compose.production.yml build

# Start services
docker-compose -f docker-compose.production.yml up -d

# Check status
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f api-server
```

## Step 7: Verify Deployment

### Health Checks

```bash
# API health
curl https://api.yourdomain.com/api/v1/health

# Prometheus metrics
curl http://localhost:9090/metrics

# Redis
docker exec aftersec-redis redis-cli ping

# PostgreSQL
docker exec aftersec-postgres-primary psql -U aftersec -d aftersec -c "SELECT version();"
```

### Monitoring Access

- **Grafana**: https://grafana.yourdomain.com (admin / $GRAFANA_PASSWORD)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

## Step 8: Production Readiness Checklist

### Security
- [ ] JWT secret is randomly generated and secure
- [ ] Database passwords are strong and unique
- [ ] TLS certificates are valid and not self-signed
- [ ] Firewall rules limit access to necessary ports only
- [ ] Redis requires authentication
- [ ] API rate limiting is enabled (Redis-based)

### Performance
- [ ] Database connection pool is configured (100 max connections)
- [ ] Redis is configured with persistence and memory limits
- [ ] PgBouncer is handling connection pooling
- [ ] API servers are scaled to 3 replicas

### Monitoring
- [ ] Prometheus is scraping all services
- [ ] Grafana dashboards are configured
- [ ] Loki is ingesting logs
- [ ] Alerts are configured for critical issues

### Backups
- [ ] OCI Object Storage bucket is configured
- [ ] Backup service is running daily
- [ ] Backup restoration has been tested
- [ ] 30-day retention is configured

### Budget Controls
- [ ] LLM budget limits are configured
- [ ] Budget tracking is initialized
- [ ] Circuit breakers are enabled
- [ ] Cost alerts are configured

## Step 9: Operations

### Daily Operations

```bash
# Check service status
docker-compose -f docker-compose.production.yml ps

# View API logs
docker-compose -f docker-compose.production.yml logs -f api-server

# Check database replication
docker exec aftersec-postgres-replica psql -U aftersec -c "SELECT pg_is_in_recovery();"

# Monitor Redis
docker exec aftersec-redis redis-cli info stats
```

### Backup and Restore

```bash
# Manual backup
docker exec aftersec-postgres-primary pg_dump -U aftersec aftersec > backup.sql

# Restore from backup
docker exec -i aftersec-postgres-primary psql -U aftersec aftersec < backup.sql
```

### Scaling

```bash
# Scale API servers
docker-compose -f docker-compose.production.yml up -d --scale api-server=5

# Scale down
docker-compose -f docker-compose.production.yml up -d --scale api-server=3
```

### Updates and Maintenance

```bash
# Pull latest code
git pull origin main

# Rebuild and deploy
docker-compose -f docker-compose.production.yml build
docker-compose -f docker-compose.production.yml up -d

# Rolling restart (zero downtime)
for i in 1 2 3; do
  docker-compose -f docker-compose.production.yml restart api-server
  sleep 30
done
```

## Troubleshooting

### API Server Won't Start

```bash
# Check logs
docker-compose -f docker-compose.production.yml logs api-server

# Check environment variables
docker-compose -f docker-compose.production.yml config

# Verify database connection
docker exec aftersec-postgres-primary psql -U aftersec -d aftersec -c "SELECT 1;"
```

### High Memory Usage

```bash
# Check Redis memory
docker exec aftersec-redis redis-cli info memory

# Check PostgreSQL connections
docker exec aftersec-postgres-primary psql -U aftersec -c "SELECT count(*) FROM pg_stat_activity;"

# Check PgBouncer stats
docker exec aftersec-pgbouncer psql -p 6432 -U aftersec pgbouncer -c "SHOW STATS;"
```

### LLM Budget Exceeded

```bash
# Check budget status
curl -H "Authorization: Bearer $JWT_TOKEN" \
  https://api.yourdomain.com/api/v1/ai/budget/stats

# Reset daily budget (if needed)
docker exec aftersec-redis redis-cli DEL budget:daily
```

## Cost Breakdown (Monthly)

| Resource | Cost |
|----------|------|
| OCI Compute (3x instances) | $1,590 |
| OCI Block Storage (3TB) | $338 |
| OCI Load Balancer | $115 |
| OCI Outbound Bandwidth (500GB) | $42 |
| Cloudflare Pro | $20 |
| DarkAPI.io | $199 |
| LLM APIs (with optimization) | $77.50 |
| **Total** | **$2,381.50** |

## Support

For issues and questions:
- GitHub Issues: https://github.com/your-org/aftersec/issues
- Documentation: https://docs.aftersec.io
- Email: support@aftersec.io
