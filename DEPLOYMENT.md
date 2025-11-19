# 🚀 Deployment Guide - Kais OUERIEMMI Auth System

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Cloud Deployment](#cloud-deployment)
6. [Security Checklist](#security-checklist)
7. [Monitoring & Maintenance](#monitoring--maintenance)

---

## Prerequisites

### Required Services
- **Node.js** >= 18.0.0
- **PostgreSQL** >= 14.0
- **Redis** >= 6.0
- **SMTP Server** (for emails)

### Optional
- **Docker** & Docker Compose (for containerized deployment)
- **Nginx** (for reverse proxy)
- **Let's Encrypt** (for SSL/TLS certificates)

---

## Local Development Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your local configuration:
- PostgreSQL credentials
- Redis connection
- SMTP settings (use Gmail with App Password for testing)

### 3. Generate JWT Keys

```bash
npm run generate:keys
```

This creates RSA key pairs in the `keys/` directory.

### 4. Setup Database

```bash
# Create database
createdb kais_auth_db

# Run schema
psql -U postgres -d kais_auth_db -f database/schema.sql
```

### 5. Start Services

**Option A: Local Services**
```bash
# Start PostgreSQL
pg_ctl start

# Start Redis
redis-server

# Start application
npm run dev
```

**Option B: Docker Compose**
```bash
docker-compose up -d
```

### 6. Verify Installation

```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "healthy",
  "services": {
    "database": "up",
    "redis": "up"
  }
}
```

---

## Production Deployment

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Redis
sudo apt install -y redis-server

# Install Nginx
sudo apt install -y nginx

# Install PM2 (process manager)
sudo npm install -g pm2
```

### 2. Application Setup

```bash
# Clone repository
git clone <your-repo-url> /var/www/kais-auth
cd /var/www/kais-auth

# Install dependencies
npm ci --only=production

# Build TypeScript
npm run build

# Generate keys
npm run generate:keys

# Set proper permissions
chmod 600 keys/*.pem
```

### 3. Environment Configuration

Create `/var/www/kais-auth/.env` with production values:

```env
NODE_ENV=production
PORT=3000
API_URL=https://api.yourdomain.com
FRONTEND_URL=https://yourdomain.com

# Use strong secrets!
SESSION_SECRET=<generate-with-openssl-rand-hex-64>
CSRF_SECRET=<generate-with-openssl-rand-hex-64>

# Enable secure cookies
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict

# Database (use strong password)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=kais_auth_db
DB_USER=kais_auth_user
DB_PASSWORD=<strong-password>
DB_SSL=true

# Redis (enable password)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=<strong-password>

# SMTP (use production email service)
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=<sendgrid-api-key>

# OAuth (production credentials)
GOOGLE_CLIENT_ID=<production-client-id>
GOOGLE_CLIENT_SECRET=<production-secret>
GITHUB_CLIENT_ID=<production-client-id>
GITHUB_CLIENT_SECRET=<production-secret>
```

### 4. Database Setup

```bash
# Create database user
sudo -u postgres psql
CREATE USER kais_auth_user WITH PASSWORD 'strong-password';
CREATE DATABASE kais_auth_db OWNER kais_auth_user;
GRANT ALL PRIVILEGES ON DATABASE kais_auth_db TO kais_auth_user;
\q

# Run migrations
psql -U kais_auth_user -d kais_auth_db -f database/schema.sql
```

### 5. Redis Configuration

```bash
# Edit Redis config
sudo nano /etc/redis/redis.conf

# Set password
requirepass <strong-password>

# Restart Redis
sudo systemctl restart redis
```

### 6. Start Application with PM2

```bash
# Start app
pm2 start dist/server.js --name kais-auth

# Save PM2 configuration
pm2 save

# Setup startup script
pm2 startup
```

### 7. Nginx Reverse Proxy

Create `/etc/nginx/sites-available/kais-auth`:

```nginx
upstream kais_auth {
    server localhost:3000;
}

server {
    listen 80;
    server_name api.yourdomain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL certificates (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy settings
    location / {
        proxy_pass http://kais_auth;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/kais-auth /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 8. SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d api.yourdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

---

## Docker Deployment

### 1. Build Image

```bash
docker build -t kais-auth:latest .
```

### 2. Run with Docker Compose

```bash
docker-compose up -d
```

### 3. Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_DB: kais_auth_db
      POSTGRES_USER: kais_auth_user
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - kais-auth-network

  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - kais-auth-network

  app:
    image: kais-auth:latest
    restart: always
    ports:
      - "3000:3000"
    env_file:
      - .env.production
    depends_on:
      - postgres
      - redis
    volumes:
      - ./keys:/app/keys:ro
      - ./logs:/app/logs
    networks:
      - kais-auth-network

secrets:
  db_password:
    file: ./secrets/db_password.txt

volumes:
  postgres_data:
  redis_data:

networks:
  kais-auth-network:
    driver: bridge
```

---

## Cloud Deployment

### AWS (EC2 + RDS + ElastiCache)

1. **Launch EC2 Instance** (t3.medium or larger)
2. **Create RDS PostgreSQL** instance
3. **Create ElastiCache Redis** cluster
4. **Configure Security Groups**
5. **Deploy application** using PM2 or Docker
6. **Setup Load Balancer** (ALB)
7. **Configure Route 53** for DNS

### Google Cloud Platform (GKE)

1. **Create GKE Cluster**
2. **Deploy PostgreSQL** (Cloud SQL)
3. **Deploy Redis** (Memorystore)
4. **Create Kubernetes manifests**
5. **Deploy with kubectl**
6. **Setup Ingress** with SSL

### Heroku

```bash
# Create app
heroku create kais-auth

# Add PostgreSQL
heroku addons:create heroku-postgresql:hobby-dev

# Add Redis
heroku addons:create heroku-redis:hobby-dev

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set SESSION_SECRET=$(openssl rand -hex 64)

# Deploy
git push heroku main
```

---

## Security Checklist

### Pre-Deployment

- [ ] Change all default secrets in `.env`
- [ ] Generate strong SESSION_SECRET and CSRF_SECRET
- [ ] Use strong database passwords
- [ ] Enable Redis password authentication
- [ ] Configure OAuth with production credentials
- [ ] Set COOKIE_SECURE=true
- [ ] Enable database SSL connections
- [ ] Review and restrict CORS origins
- [ ] Set proper file permissions (600 for keys)
- [ ] Disable unnecessary services

### Post-Deployment

- [ ] Enable HTTPS everywhere
- [ ] Configure firewall (UFW/iptables)
- [ ] Setup fail2ban for brute force protection
- [ ] Enable automatic security updates
- [ ] Configure log rotation
- [ ] Setup monitoring and alerts
- [ ] Implement backup strategy
- [ ] Test disaster recovery
- [ ] Perform security audit
- [ ] Setup intrusion detection (OSSEC/Wazuh)

### Ongoing

- [ ] Regular dependency updates (`npm audit`)
- [ ] Monitor security advisories
- [ ] Review audit logs weekly
- [ ] Rotate JWT keys quarterly
- [ ] Test backups monthly
- [ ] Security penetration testing annually

---

## Monitoring & Maintenance

### Logging

```bash
# View PM2 logs
pm2 logs kais-auth

# View application logs
tail -f logs/app.log

# View error logs
tail -f logs/error.log
```

### Monitoring Tools

- **PM2 Plus** - Application monitoring
- **Datadog** - Infrastructure monitoring
- **Sentry** - Error tracking
- **Prometheus + Grafana** - Metrics visualization

### Database Maintenance

```bash
# Backup database
pg_dump -U kais_auth_user kais_auth_db > backup_$(date +%Y%m%d).sql

# Cleanup expired tokens (run daily via cron)
psql -U kais_auth_user -d kais_auth_db -c "SELECT cleanup_expired_tokens();"
```

### Health Checks

```bash
# Application health
curl https://api.yourdomain.com/health

# Database connection
psql -U kais_auth_user -d kais_auth_db -c "SELECT 1;"

# Redis connection
redis-cli -a <password> ping
```

---

## Troubleshooting

### Application Won't Start

```bash
# Check logs
pm2 logs kais-auth --lines 100

# Check environment
node -v
npm -v

# Verify database connection
psql -U kais_auth_user -d kais_auth_db
```

### High Memory Usage

```bash
# Check PM2 status
pm2 status

# Restart application
pm2 restart kais-auth

# Monitor memory
pm2 monit
```

### Database Connection Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connections
psql -U postgres -c "SELECT * FROM pg_stat_activity;"
```

---

## Support

For issues or questions:
- Check the main README.md
- Review application logs
- Open an issue on GitHub

**Author:** Kais OUERIEMMI
