# 🔐 Kais OUERIEMMI Authentication System

A **production-ready, enterprise-grade authentication and authorization system** with comprehensive security hardening, OAuth2/OpenID Connect social login, MFA, and full audit logging.

**Author:** Kais OUERIEMMI  
**Version:** 1.0.0  
**License:** MIT

---

## ✨ Features

### Core Authentication
- ✅ **Email/Password Registration & Login** with Argon2id hashing
- ✅ **Email Verification** with secure token-based flow
- ✅ **Password Reset** with time-limited tokens
- ✅ **Magic Links** for passwordless authentication
- ✅ **Account Locking** after configurable failed login attempts
- ✅ **Password Complexity** enforcement with strength scoring

### OAuth2 & Social Login
- ✅ **Google OAuth2** with OpenID Connect
- ✅ **GitHub OAuth2** integration
- ✅ **Provider Linking/Unlinking** to existing accounts
- ✅ **PKCE Support** for SPAs and mobile apps
- ✅ **State & Nonce Validation** for CSRF protection

### Multi-Factor Authentication (MFA)
- ✅ **TOTP (Time-based One-Time Password)** with QR codes
- ✅ **Backup Recovery Codes** (hashed storage)
- ✅ **Authenticator App Support** (Google Authenticator, Authy, etc.)

### Token Management
- ✅ **JWT Access Tokens** (RS256, 15-minute expiry)
- ✅ **Refresh Token Rotation** with reuse detection
- ✅ **Token Revocation** and family invalidation
- ✅ **Session Management** with device tracking

### Security Features
- ✅ **Argon2id Password Hashing** (64MB memory, 3 iterations)
- ✅ **Redis-backed Rate Limiting** (token bucket algorithm)
- ✅ **CSRF Protection** (double-submit cookie)
- ✅ **Secure HTTP Headers** (HSTS, CSP, X-Frame-Options)
- ✅ **SameSite Cookies** (Strict mode)
- ✅ **Input Validation** with express-validator
- ✅ **SQL Injection Prevention** (parameterized queries)
- ✅ **XSS Protection** with output encoding

### Audit & Compliance
- ✅ **Immutable Audit Logs** for all security events
- ✅ **IP & Device Tracking** for sessions
- ✅ **Security Alerts** via email
- ✅ **GDPR Compliance** considerations (data retention, consent)
- ✅ **Role-Based Access Control (RBAC)**

### Monitoring & Operations
- ✅ **Structured Logging** with Winston
- ✅ **Health Check Endpoints**
- ✅ **Graceful Shutdown** handling
- ✅ **Database Connection Pooling**
- ✅ **Automated Token Cleanup**

---

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Client    │────▶│  Express API │────▶│ PostgreSQL  │
│  (Browser)  │     │   (Node.js)  │     │  Database   │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                           ├────▶ Redis (Rate Limiting & Sessions)
                           ├────▶ SMTP (Email Service)
                           └────▶ OAuth Providers (Google, GitHub)
```

### Tech Stack
- **Runtime:** Node.js 18+ with TypeScript
- **Framework:** Express.js
- **Database:** PostgreSQL 14+
- **Cache:** Redis 6+
- **Authentication:** Passport.js, JWT (RS256)
- **Password Hashing:** Argon2id
- **MFA:** OTPLib (TOTP)
- **Email:** Nodemailer
- **Testing:** Jest + Supertest

---

## 📋 Prerequisites

- **Node.js** >= 18.0.0
- **PostgreSQL** >= 14.0
- **Redis** >= 6.0
- **npm** >= 9.0.0

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
cd c:\Users\USER\OneDrive\Desktop\Kais\Projects\Auth\Auth
npm install
```

### 2. Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` and configure:
- Database credentials (PostgreSQL)
- Redis connection
- SMTP settings for email
- OAuth credentials (Google & GitHub)
- JWT key paths

### 3. Generate RSA Keys

```bash
npm run generate:keys
```

This creates RS256 key pairs for JWT signing:
- `keys/access-token-private.pem`
- `keys/access-token-public.pem`
- `keys/refresh-token-private.pem`
- `keys/refresh-token-public.pem`

### 4. Database Setup

```bash
# Create database
createdb kais_auth_db

# Run migrations
psql -U postgres -d kais_auth_db -f database/schema.sql
```

### 5. Start Development Server

```bash
npm run dev
```

Server will start on `http://localhost:3000`

---

## 📡 API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | Login with email/password | No |
| POST | `/api/auth/logout` | Logout current session | Yes |
| POST | `/api/auth/refresh-token` | Refresh access token | No (refresh token) |
| POST | `/api/auth/forgot-password` | Request password reset | No |
| POST | `/api/auth/reset-password` | Reset password with token | No |
| GET | `/api/auth/verify-email` | Verify email address | No |

### OAuth2

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/oauth/google` | Initiate Google OAuth |
| GET | `/api/auth/oauth/google/callback` | Google OAuth callback |
| GET | `/api/auth/oauth/github` | Initiate GitHub OAuth |
| GET | `/api/auth/oauth/github/callback` | GitHub OAuth callback |
| POST | `/api/auth/link-provider` | Link OAuth provider to account |
| POST | `/api/auth/unlink-provider` | Unlink OAuth provider |

### Session Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/auth/sessions` | Get all active sessions | Yes |
| DELETE | `/api/auth/sessions/:id` | Terminate specific session | Yes |

### Admin

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/auth/users/:id/roles` | Get user roles | Yes (Admin) |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/csrf-token` | Get CSRF token |

---

## 🔑 OAuth2 Setup

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable **Google+ API**
4. Create OAuth 2.0 credentials:
   - **Authorized redirect URIs:** `http://localhost:3000/api/auth/oauth/google/callback`
   - **Scopes:** `openid`, `email`, `profile`
5. Copy **Client ID** and **Client Secret** to `.env`

### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App:
   - **Authorization callback URL:** `http://localhost:3000/api/auth/oauth/github/callback`
3. Copy **Client ID** and **Client Secret** to `.env`

---

## 🔒 Security Configuration

### Password Policy

```env
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=true
```

### Account Lockout

```env
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=900000  # 15 minutes in ms
```

### Rate Limiting

```env
# General API: 100 requests per 15 minutes
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Auth endpoints: 5 requests per 15 minutes
AUTH_RATE_LIMIT_WINDOW_MS=900000
AUTH_RATE_LIMIT_MAX_REQUESTS=5
```

### JWT Configuration

```env
JWT_ACCESS_TOKEN_EXPIRY=15m   # Short-lived
JWT_REFRESH_TOKEN_EXPIRY=7d   # Long-lived
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Run security tests only
npm run test:security

# Watch mode
npm run test:watch
```

---

## 📊 Database Schema

### Key Tables

- **users** - User accounts with security metadata
- **oauth_identities** - Linked OAuth provider accounts
- **refresh_tokens** - Hashed refresh tokens with rotation tracking
- **sessions** - Active user sessions with device info
- **audit_logs** - Immutable security event logs
- **roles** & **user_roles** - RBAC implementation

See `database/schema.sql` for complete schema.

---

## 🔐 Security Best Practices

### Production Checklist

- [ ] Change all default secrets in `.env`
- [ ] Enable HTTPS (set `COOKIE_SECURE=true`)
- [ ] Configure proper CORS origins
- [ ] Set up SSL/TLS for database connections
- [ ] Enable Redis password authentication
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerting
- [ ] Enable automated backups
- [ ] Review and test disaster recovery
- [ ] Implement log aggregation
- [ ] Set up intrusion detection
- [ ] Regular security audits
- [ ] Keep dependencies updated (`npm audit`)

### Key Rotation

Rotate JWT keys periodically:

```bash
npm run generate:keys
# Backup old keys before replacing
```

---

## 📝 Environment Variables Reference

See `.env.example` for complete list with descriptions.

### Critical Variables

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=kais_auth_db
DB_USER=postgres
DB_PASSWORD=your_secure_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Security
SESSION_SECRET=your_super_secret_session_key
CSRF_SECRET=your_csrf_secret

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password

# OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

---

## 🐛 Troubleshooting

### JWT Keys Not Found

```bash
npm run generate:keys
```

### Database Connection Failed

Check PostgreSQL is running:
```bash
pg_isready
```

### Redis Connection Failed

Check Redis is running:
```bash
redis-cli ping
```

### Email Not Sending

- Verify SMTP credentials
- For Gmail, use [App Passwords](https://support.google.com/accounts/answer/185833)
- Check firewall allows outbound SMTP

---

## 📚 Additional Resources

- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OAuth 2.0 Security](https://tools.ietf.org/html/rfc6749)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)

---

## 📄 License

MIT License - Copyright (c) 2025 Kais OUERIEMMI

---

## 👤 Author

**Kais OUERIEMMI**

For questions or support, please open an issue on the repository.

---

## 🎯 Roadmap

- [ ] WebAuthn/FIDO2 support
- [ ] SMS-based MFA
- [ ] Biometric authentication
- [ ] Advanced RBAC with permissions
- [ ] API key management
- [ ] OAuth2 as a provider
- [ ] SAML support
- [ ] GraphQL API
- [ ] Mobile SDKs
- [ ] Admin dashboard UI

---

**Built with ❤️ by Kais OUERIEMMI**