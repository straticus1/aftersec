# AfterSec Deployment Guide

Complete guide for deploying AfterSec in development, staging, and production environments.

## Table of Contents

1. [Quick Start (Development)](#quick-start-development)
2. [Production Deployment](#production-deployment)
3. [Security Hardening](#security-hardening)
4. [Monitoring & Logging](#monitoring--logging)
5. [Scaling](#scaling)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start (Development)

### Prerequisites

- Docker and Docker Compose
- Go 1.22+ (for local development)
- Node.js 18+ (for dashboard development)

### Local Development with Docker

```bash
# 1. Clone and navigate to the repository
cd /path/to/aftersec

# 2. Start all services
docker-compose up -d

# 3. Verify services are running
docker-compose ps

# 4. Check logs
docker-compose logs -f server

# 5. Access the dashboard
open http://localhost:3000
```

### Local Development without Docker

```bash
# 1. Start PostgreSQL
docker run -d \
  --name aftersec-db \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=aftersec \
  -p 5432:5432 \
  postgres:15-alpine

# 2. Build and run the server
./build.sh server
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/aftersec?sslmode=disable"
./aftersec-server

# 3. Run the dashboard (in another terminal)
cd aftersec-dashboard
npm install
npm run dev
```

---

## Production Deployment

### Prerequisites

1. **Server Requirements**
   - Ubuntu 22.04 LTS or similar
   - 4 CPU cores minimum
   - 8 GB RAM minimum
   - 100 GB SSD storage
   - Public IP address with firewall configured

2. **Domain & DNS**
   - Domain name (e.g., `aftersec.example.com`)
   - DNS A record pointing to server IP
   - Subdomain for dashboard (e.g., `dashboard.aftersec.example.com`)

3. **TLS Certificates**
   - Production TLS certificates (Let's Encrypt recommended)
   - Or generate self-signed certificates for private deployment

### Step 1: Generate Production Certificates

```bash
# Generate certificates with CA for mTLS
./scripts/generate-certs.sh ./certs 3650

# Verify certificates
openssl verify -CAfile certs/ca.crt certs/server.crt
openssl verify -CAfile certs/ca.crt certs/client.crt

# Set proper permissions
chmod 600 certs/server.key certs/client.key certs/ca.key
chmod 644 certs/server.crt certs/client.crt certs/ca.crt
```

### Step 2: Configure Environment Variables

Create `.env` file in project root:

```bash
# Database Configuration
DATABASE_URL=postgres://aftersec:STRONG_PASSWORD_HERE@db:5432/aftersec?sslmode=require

# Security Configuration
MTLS_ENABLED=true
JWT_SECRET=GENERATE_SECURE_RANDOM_STRING_HERE

# Server Configuration
REST_PORT=8080
GRPC_PORT=9090

# Dashboard Configuration
NEXT_PUBLIC_API_URL=https://api.aftersec.example.com/api/v1
```

### Step 3: Configure Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_USER: aftersec
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: aftersec
    volumes:
      - aftersec_data:/var/lib/postgresql/data
      - ./backups:/backups
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aftersec"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - aftersec-network

  server:
    build:
      context: .
      dockerfile: Dockerfile.server
    restart: always
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - MTLS_ENABLED=true
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - ./certs:/app/certs:ro
      - ./migrations:/app/migrations:ro
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - aftersec-network

  dashboard:
    build:
      context: .
      dockerfile: Dockerfile.dashboard
    restart: always
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=https://api.aftersec.example.com/api/v1
      - NODE_ENV=production
    depends_on:
      - server
    networks:
      - aftersec-network

volumes:
  aftersec_data:

networks:
  aftersec-network:
    driver: bridge
```

### Step 4: Deploy with Docker Compose

```bash
# 1. Pull latest code
git pull origin main

# 2. Build images
docker-compose -f docker-compose.prod.yml build

# 3. Start services
docker-compose -f docker-compose.prod.yml up -d

# 4. Verify deployment
docker-compose -f docker-compose.prod.yml ps
docker-compose -f docker-compose.prod.yml logs -f server

# 5. Test health endpoint
curl http://localhost:8080/api/v1/health
```

### Step 5: Configure Reverse Proxy (Nginx)

Install and configure Nginx as reverse proxy:

```bash
# Install Nginx
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx

# Create Nginx configuration
sudo nano /etc/nginx/sites-available/aftersec
```

```nginx
# API Server
server {
    listen 80;
    server_name api.aftersec.example.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Dashboard
server {
    listen 80;
    server_name dashboard.aftersec.example.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/aftersec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get Let's Encrypt certificates
sudo certbot --nginx -d api.aftersec.example.com -d dashboard.aftersec.example.com
```

---

## Security Hardening

### 1. Database Security

```bash
# Connect to database container
docker exec -it aftersec-db-1 psql -U aftersec

# Create read-only user for analytics
CREATE USER aftersec_reader WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE aftersec TO aftersec_reader;
GRANT USAGE ON SCHEMA public TO aftersec_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO aftersec_reader;
```

### 2. Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (for Let's Encrypt)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### 3. mTLS Client Setup

Distribute client certificates to authorized endpoints:

```bash
# Copy client certificates to endpoint
scp certs/ca.crt certs/client.crt certs/client.key endpoint@192.168.1.100:/etc/aftersec/certs/

# Configure endpoint to use mTLS
export AFTERSEC_SERVER=api.aftersec.example.com:9090
export AFTERSEC_CA_CERT=/etc/aftersec/certs/ca.crt
export AFTERSEC_CLIENT_CERT=/etc/aftersec/certs/client.crt
export AFTERSEC_CLIENT_KEY=/etc/aftersec/certs/client.key
```

### 4. Rate Limiting

Add rate limiting to Nginx:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

    server {
        location /api/ {
            limit_req zone=api_limit burst=20 nodelay;
            # ... rest of config
        }
    }
}
```

---

## Monitoring & Logging

### Application Logs

```bash
# View server logs
docker-compose logs -f server

# View database logs
docker-compose logs -f db

# Export logs to file
docker-compose logs server > server.log

# Follow logs with grep filter
docker-compose logs -f server | grep ERROR
```

### Health Checks

```bash
# Check service health
curl http://localhost:8080/api/v1/health

# Check database connectivity
docker exec aftersec-db-1 pg_isready -U aftersec

# Check gRPC service
grpcurl -plaintext localhost:9090 list
```

### Database Backups

```bash
# Manual backup
docker exec aftersec-db-1 pg_dump -U aftersec aftersec > backup_$(date +%Y%m%d).sql

# Automated daily backups (cron)
0 2 * * * docker exec aftersec-db-1 pg_dump -U aftersec aftersec > /backups/backup_$(date +\%Y\%m\%d).sql
```

---

## Scaling

### Horizontal Scaling (Multiple Server Instances)

1. **Setup Load Balancer** (Nginx, HAProxy, or cloud LB)
2. **Shared Database** (PostgreSQL with connection pooling)
3. **Redis for Session Storage** (add to docker-compose)
4. **Distributed gRPC** (service mesh like Istio)

Example with multiple server instances:

```yaml
services:
  server-1:
    # ... same as server config

  server-2:
    # ... same as server config

  nginx-lb:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
```

### Vertical Scaling (Resource Limits)

```yaml
services:
  server:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

---

## Troubleshooting

### Server Won't Start

```bash
# Check logs
docker-compose logs server

# Common issues:
# 1. Database not ready
docker-compose restart db
sleep 10
docker-compose restart server

# 2. TLS certificate issues
ls -la certs/
openssl verify -CAfile certs/ca.crt certs/server.crt

# 3. Port already in use
sudo lsof -i :8080
sudo lsof -i :9090
```

### Client Can't Connect

```bash
# 1. Verify server is listening
netstat -tlnp | grep 9090

# 2. Test gRPC connectivity
grpcurl -insecure localhost:9090 list

# 3. Check firewall
sudo ufw status

# 4. Verify mTLS certificates
openssl s_client -connect localhost:9090 \
  -cert certs/client.crt \
  -key certs/client.key \
  -CAfile certs/ca.crt
```

### Database Connection Issues

```bash
# 1. Check database is running
docker-compose ps db

# 2. Test connection
docker exec -it aftersec-db-1 psql -U aftersec

# 3. Check DATABASE_URL environment variable
docker exec aftersec-server-1 env | grep DATABASE_URL

# 4. Verify network connectivity
docker network inspect aftersec_default
```

### Performance Issues

```bash
# 1. Check resource usage
docker stats

# 2. Database query performance
docker exec -it aftersec-db-1 psql -U aftersec -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"

# 3. Enable query logging temporarily
docker exec -it aftersec-db-1 psql -U aftersec -c "ALTER SYSTEM SET log_min_duration_statement = 1000;"
```

---

## Environment-Specific Configurations

### Development

```bash
MTLS_ENABLED=false
JWT_SECRET=dev-secret-not-for-production
DATABASE_URL=postgres://postgres:postgres@localhost:5432/aftersec?sslmode=disable
```

### Staging

```bash
MTLS_ENABLED=true
JWT_SECRET=staging-secret-change-this
DATABASE_URL=postgres://aftersec:password@staging-db:5432/aftersec?sslmode=require
```

### Production

```bash
MTLS_ENABLED=true
JWT_SECRET=$(openssl rand -base64 32)
DATABASE_URL=postgres://aftersec:$(vault kv get -field=password secret/db)@prod-db:5432/aftersec?sslmode=require
```

---

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourorg/aftersec/issues
- Documentation: https://docs.aftersec.io
- Email: support@aftersec.io
