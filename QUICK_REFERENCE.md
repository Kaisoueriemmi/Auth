# 🚀 Quick Reference Guide - Kais OUERIEMMI Auth System

## Common Commands

### Development
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run security tests
npm run test:security

# Lint code
npm run lint

# Build for production
npm run build
```

### Database
```bash
# Create database
createdb kais_auth_db

# Run schema
psql -U postgres -d kais_auth_db -f database/schema.sql

# Backup database
pg_dump -U postgres kais_auth_db > backup.sql

# Restore database
psql -U postgres kais_auth_db < backup.sql

# Connect to database
psql -U postgres -d kais_auth_db

# Cleanup expired tokens
psql -U postgres -d kais_auth_db -c "SELECT cleanup_expired_tokens();"
```

### Docker
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# View logs
docker-compose logs -f app

# Rebuild containers
docker-compose up -d --build

# Remove volumes
docker-compose down -v
```

### Production (PM2)
```bash
# Start application
pm2 start dist/server.js --name kais-auth

# Stop application
pm2 stop kais-auth

# Restart application
pm2 restart kais-auth

# View logs
pm2 logs kais-auth

# Monitor
pm2 monit

# Save configuration
pm2 save

# Setup startup script
pm2 startup
```

---

## Environment Setup

### 1. Copy Environment File
```bash
cp .env.example .env
```

### 2. Generate JWT Keys
```bash
npm run generate:keys
```

### 3. Configure OAuth

**Google:**
1. Go to https://console.cloud.google.com/
2. Create OAuth 2.0 credentials
3. Add to `.env`:
```env
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_secret
```

**GitHub:**
1. Go to https://github.com/settings/developers
2. Create OAuth App
3. Add to `.env`:
```env
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_secret
```

### 4. Configure Email (Gmail Example)
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

Get App Password: https://support.google.com/accounts/answer/185833

---

## API Testing

### Using cURL

**Register:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "username": "testuser",
    "fullName": "Test User"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

**Get Sessions:**
```bash
curl -X GET http://localhost:3000/api/auth/sessions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -b cookies.txt
```

**Health Check:**
```bash
curl http://localhost:3000/health
```

---

## Troubleshooting

### Application Won't Start

**Check Node version:**
```bash
node -v  # Should be >= 18.0.0
```

**Check dependencies:**
```bash
npm install
```

**Check environment:**
```bash
cat .env
```

**Check logs:**
```bash
tail -f logs/app.log
tail -f logs/error.log
```

### Database Connection Failed

**Check PostgreSQL is running:**
```bash
pg_isready
sudo systemctl status postgresql
```

**Test connection:**
```bash
psql -U postgres -d kais_auth_db -c "SELECT 1;"
```

**Check credentials in `.env`:**
```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=kais_auth_db
DB_USER=postgres
DB_PASSWORD=your_password
```

### Redis Connection Failed

**Check Redis is running:**
```bash
redis-cli ping  # Should return PONG
sudo systemctl status redis
```

**Test connection:**
```bash
redis-cli
> PING
> AUTH your_password
> PING
```

### JWT Keys Not Found

**Generate keys:**
```bash
npm run generate:keys
```

**Check keys exist:**
```bash
ls -la keys/
```

Should see:
- access-token-private.pem
- access-token-public.pem
- refresh-token-private.pem
- refresh-token-public.pem

### Email Not Sending

**Test SMTP connection:**
```bash
telnet smtp.gmail.com 587
```

**For Gmail:**
1. Enable 2FA
2. Generate App Password
3. Use App Password in `.env`

**Check logs:**
```bash
grep -i "email" logs/app.log
```

### Rate Limit Issues

**Clear rate limits in Redis:**
```bash
redis-cli
> KEYS rate_limit:*
> DEL rate_limit:ip:127.0.0.1
```

**Adjust limits in `.env`:**
```env
RATE_LIMIT_MAX_REQUESTS=1000
AUTH_RATE_LIMIT_MAX_REQUESTS=50
```

---

## Security Checklist

### Development
- [ ] Use `.env` file (not `.env.example`)
- [ ] Generate unique JWT keys
- [ ] Use local database
- [ ] Test OAuth with localhost URLs

### Production
- [ ] Change all secrets in `.env`
- [ ] Use strong database passwords
- [ ] Enable Redis password
- [ ] Set `COOKIE_SECURE=true`
- [ ] Set `NODE_ENV=production`
- [ ] Use production OAuth credentials
- [ ] Enable HTTPS
- [ ] Configure firewall
- [ ] Set up monitoring
- [ ] Enable automatic backups

---

## Monitoring

### Check Application Health
```bash
curl http://localhost:3000/health
```

### View Logs
```bash
# Application logs
tail -f logs/app.log

# Error logs
tail -f logs/error.log

# PM2 logs
pm2 logs kais-auth

# Docker logs
docker-compose logs -f app
```

### Database Monitoring
```bash
# Active connections
psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"

# Database size
psql -U postgres -c "SELECT pg_size_pretty(pg_database_size('kais_auth_db'));"

# Table sizes
psql -U postgres -d kais_auth_db -c "
  SELECT tablename, pg_size_pretty(pg_total_relation_size(tablename::text))
  FROM pg_tables WHERE schemaname = 'public'
  ORDER BY pg_total_relation_size(tablename::text) DESC;
"
```

### Redis Monitoring
```bash
redis-cli INFO stats
redis-cli INFO memory
redis-cli DBSIZE
```

---

## Maintenance Tasks

### Daily
```bash
# Check application health
curl http://localhost:3000/health

# Check logs for errors
grep -i "error" logs/app.log | tail -20

# Monitor disk space
df -h
```

### Weekly
```bash
# Review audit logs
psql -U postgres -d kais_auth_db -c "
  SELECT event_type, COUNT(*) 
  FROM audit_logs 
  WHERE created_at > NOW() - INTERVAL '7 days'
  GROUP BY event_type;
"

# Check for suspicious activity
psql -U postgres -d kais_auth_db -c "
  SELECT * FROM audit_logs 
  WHERE severity = 'critical' 
  AND created_at > NOW() - INTERVAL '7 days';
"

# Cleanup expired tokens
psql -U postgres -d kais_auth_db -c "SELECT cleanup_expired_tokens();"
```

### Monthly
```bash
# Update dependencies
npm audit
npm update

# Backup database
pg_dump -U postgres kais_auth_db > backup_$(date +%Y%m%d).sql

# Review and rotate logs
find logs/ -name "*.log" -mtime +30 -delete
```

### Quarterly
```bash
# Rotate JWT keys
npm run generate:keys
# Deploy new keys with zero-downtime strategy

# Security audit
npm audit --audit-level=moderate
```

---

## Performance Optimization

### Database Indexes
```sql
-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC;

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@example.com';
```

### Redis Optimization
```bash
# Check memory usage
redis-cli INFO memory

# Check slow queries
redis-cli SLOWLOG GET 10

# Flush unused keys
redis-cli --scan --pattern "rate_limit:*" | xargs redis-cli DEL
```

### Application Optimization
```bash
# Profile with clinic
npm install -g clinic
clinic doctor -- node dist/server.js

# Memory profiling
node --inspect dist/server.js
```

---

## Backup & Recovery

### Backup
```bash
# Database
pg_dump -U postgres kais_auth_db > backup.sql

# Keys (IMPORTANT!)
tar -czf keys_backup.tar.gz keys/

# Environment
cp .env .env.backup

# Complete backup
tar -czf complete_backup_$(date +%Y%m%d).tar.gz \
  database/ keys/ .env logs/
```

### Recovery
```bash
# Restore database
psql -U postgres kais_auth_db < backup.sql

# Restore keys
tar -xzf keys_backup.tar.gz

# Restore environment
cp .env.backup .env
```

---

## Useful SQL Queries

### User Statistics
```sql
-- Total users
SELECT COUNT(*) FROM users;

-- Users registered today
SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE;

-- Email verification rate
SELECT 
  COUNT(CASE WHEN email_verified THEN 1 END)::float / COUNT(*) * 100 as verification_rate
FROM users;

-- MFA adoption rate
SELECT 
  COUNT(CASE WHEN mfa_enabled THEN 1 END)::float / COUNT(*) * 100 as mfa_rate
FROM users;
```

### Security Audit
```sql
-- Failed login attempts today
SELECT COUNT(*) FROM audit_logs 
WHERE event_type = 'login_failed' 
AND created_at::date = CURRENT_DATE;

-- Locked accounts
SELECT id, email, locked_until FROM users WHERE is_locked = TRUE;

-- Recent password resets
SELECT user_id, created_at FROM password_reset_tokens 
WHERE created_at > NOW() - INTERVAL '24 hours';
```

### Session Management
```sql
-- Active sessions
SELECT COUNT(*) FROM sessions WHERE is_active = TRUE;

-- Sessions by device type
SELECT device_type, COUNT(*) FROM sessions 
WHERE is_active = TRUE 
GROUP BY device_type;

-- Expired sessions
DELETE FROM sessions WHERE expires_at < NOW();
```

---

## Quick Links

- **Main Docs:** [README.md](README.md)
- **API Docs:** [API.md](API.md)
- **Deployment:** [DEPLOYMENT.md](DEPLOYMENT.md)
- **Summary:** [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)

---

**Author:** Kais OUERIEMMI  
**Version:** 1.0.0
