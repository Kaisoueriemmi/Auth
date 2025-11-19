# 📚 API Documentation - Kais OUERIEMMI Auth System

## Base URL
```
Development: http://localhost:3000/api
Production: https://api.yourdomain.com/api
```

## Authentication
Most endpoints require a valid JWT access token in the Authorization header:
```
Authorization: Bearer <access_token>
```

Or via HttpOnly cookie (automatically set after login).

---

## Table of Contents
1. [Authentication Endpoints](#authentication-endpoints)
2. [OAuth2 Endpoints](#oauth2-endpoints)
3. [Session Management](#session-management)
4. [Admin Endpoints](#admin-endpoints)
5. [Error Responses](#error-responses)
6. [Rate Limiting](#rate-limiting)

---

## Authentication Endpoints

### Register User
Create a new user account.

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "username": "johndoe",
  "fullName": "John Doe"
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "message": "Registration successful. Please check your email to verify your account.",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "username": "johndoe",
      "fullName": "John Doe",
      "emailVerified": false
    }
  }
}
```

**Validation Rules:**
- Email: Valid email format
- Password: Minimum 12 characters, must include uppercase, lowercase, numbers, and symbols
- Username: 3-30 alphanumeric characters

---

### Login
Authenticate with email and password.

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "mfaCode": "123456"  // Optional, required if MFA is enabled
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "emailVerified": true
    }
  }
}
```

**MFA Required Response:** `200 OK`
```json
{
  "success": true,
  "requiresMFA": true,
  "message": "MFA code required"
}
```

**Error Responses:**
- `401 Unauthorized` - Invalid credentials
- `403 Forbidden` - Account locked or inactive
- `429 Too Many Requests` - Rate limit exceeded

---

### Logout
Terminate the current session.

**Endpoint:** `POST /auth/logout`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Logout successful"
}
```

---

### Refresh Access Token
Get a new access token using a refresh token.

**Endpoint:** `POST /auth/refresh-token`

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Or send via HttpOnly cookie (automatically included).

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Security Features:**
- Automatic token rotation
- Reuse detection (revokes entire token family if detected)
- Hashed storage in database

---

### Forgot Password
Request a password reset link.

**Endpoint:** `POST /auth/forgot-password`

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "If an account exists with this email, a password reset link has been sent."
}
```

**Note:** Always returns success to prevent email enumeration.

---

### Reset Password
Reset password using a token from email.

**Endpoint:** `POST /auth/reset-password`

**Request Body:**
```json
{
  "token": "secure-reset-token",
  "newPassword": "NewSecurePassword123!"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Password has been reset successfully. Please log in with your new password."
}
```

**Security:**
- Token expires after 1 hour
- Single-use tokens
- All existing sessions are revoked
- Security alert email sent

---

### Verify Email
Verify email address using token from email.

**Endpoint:** `GET /auth/verify-email?token=<token>`

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Email verified successfully. You can now log in."
}
```

---

## OAuth2 Endpoints

### Initiate Google OAuth
Redirect user to Google login.

**Endpoint:** `GET /auth/oauth/google`

**Response:** Redirects to Google OAuth consent screen

---

### Google OAuth Callback
Handle Google OAuth callback (automatic).

**Endpoint:** `GET /auth/oauth/google/callback`

**Response:** Redirects to frontend with session cookies set

---

### Initiate GitHub OAuth
Redirect user to GitHub login.

**Endpoint:** `GET /auth/oauth/github`

**Response:** Redirects to GitHub OAuth authorization

---

### GitHub OAuth Callback
Handle GitHub OAuth callback (automatic).

**Endpoint:** `GET /auth/oauth/github/callback`

**Response:** Redirects to frontend with session cookies set

---

### Link OAuth Provider
Link Google or GitHub account to existing user.

**Endpoint:** `POST /auth/link-provider`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "provider": "google",
  "providerUserId": "google-user-id",
  "accessToken": "provider-access-token",
  "refreshToken": "provider-refresh-token",
  "profileData": { ... }
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "google account linked successfully"
}
```

---

### Unlink OAuth Provider
Remove linked OAuth provider.

**Endpoint:** `POST /auth/unlink-provider`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "provider": "google"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "google account unlinked successfully"
}
```

**Safety:** Cannot unlink if it's the only authentication method.

---

## Session Management

### Get All Sessions
List all active sessions for the current user.

**Endpoint:** `GET /auth/sessions`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "session-uuid",
        "deviceName": "Chrome on Windows",
        "deviceType": "web",
        "ipAddress": "192.168.1.1",
        "createdAt": "2025-01-01T00:00:00.000Z",
        "lastActivity": "2025-01-01T12:00:00.000Z",
        "expiresAt": "2025-01-08T00:00:00.000Z"
      }
    ]
  }
}
```

---

### Terminate Session
Revoke a specific session.

**Endpoint:** `DELETE /auth/sessions/:id`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Session terminated"
}
```

---

## Admin Endpoints

### Get User Roles
Retrieve roles for a specific user (admin only).

**Endpoint:** `GET /auth/users/:id/roles`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "roles": [
      {
        "name": "user",
        "description": "Standard user role",
        "assignedAt": "2025-01-01T00:00:00.000Z"
      }
    ]
  }
}
```

**Authorization:** Requires `admin` role.

---

## Error Responses

### Standard Error Format
```json
{
  "success": false,
  "error": "ErrorCode",
  "message": "Human-readable error message",
  "errors": [  // Optional, for validation errors
    {
      "field": "email",
      "message": "Valid email is required"
    }
  ]
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `ValidationError` | 400 | Invalid request data |
| `Unauthorized` | 401 | Missing or invalid authentication |
| `TokenExpired` | 401 | Access token has expired |
| `InvalidCredentials` | 401 | Wrong email or password |
| `Forbidden` | 403 | Insufficient permissions |
| `AccountLocked` | 403 | Too many failed login attempts |
| `EmailNotVerified` | 403 | Email verification required |
| `NotFound` | 404 | Resource not found |
| `UserExists` | 409 | Email or username already taken |
| `TooManyRequests` | 429 | Rate limit exceeded |
| `InternalServerError` | 500 | Server error |

---

## Rate Limiting

### Limits

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| General API | 100 requests | 15 minutes |
| Authentication | 5 requests | 15 minutes |
| Password Reset | 3 requests | 1 hour |

### Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
Retry-After: 900
```

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": "Too many requests",
  "message": "Rate limit exceeded. Please try again in 900 seconds.",
  "retryAfter": 900
}
```

---

## CSRF Protection

### Get CSRF Token

**Endpoint:** `GET /api/csrf-token`

**Response:** `200 OK`
```json
{
  "success": true,
  "csrfToken": "random-csrf-token"
}
```

### Using CSRF Token

Include in request header:
```
X-CSRF-Token: <csrf-token>
```

Or the token is automatically included via cookie for same-origin requests.

---

## Security Best Practices

### For Clients

1. **Store tokens securely:**
   - Web: Use HttpOnly cookies (automatic)
   - Mobile: Use OS keychain/keystore
   - Never store in localStorage

2. **Handle token expiration:**
   - Implement automatic refresh token flow
   - Redirect to login on 401 errors

3. **Implement PKCE for SPAs:**
   - Use code verifier/challenge for OAuth flows

4. **Validate SSL certificates:**
   - Always use HTTPS in production

### For API Consumers

1. **Respect rate limits:**
   - Implement exponential backoff
   - Cache responses when possible

2. **Handle errors gracefully:**
   - Show user-friendly messages
   - Log errors for debugging

3. **Implement timeout handling:**
   - Set reasonable request timeouts
   - Retry failed requests with backoff

---

## Example Workflows

### Complete Registration Flow

```javascript
// 1. Register
const registerResponse = await fetch('/api/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass123!',
    username: 'johndoe',
    fullName: 'John Doe'
  })
});

// 2. User receives email and clicks verification link
// GET /api/auth/verify-email?token=<token>

// 3. User can now login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',  // Include cookies
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass123!'
  })
});

const { accessToken } = await loginResponse.json();
```

### Token Refresh Flow

```javascript
// Automatic refresh when access token expires
async function refreshAccessToken() {
  const response = await fetch('/api/auth/refresh-token', {
    method: 'POST',
    credentials: 'include'  // Sends refresh token cookie
  });
  
  if (!response.ok) {
    // Refresh token expired, redirect to login
    window.location.href = '/login';
    return null;
  }
  
  const { accessToken } = await response.json();
  return accessToken;
}
```

---

## Postman Collection

Import this collection to test the API:

```json
{
  "info": {
    "name": "Kais OUERIEMMI Auth API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Register",
      "request": {
        "method": "POST",
        "url": "{{baseUrl}}/auth/register",
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"SecurePass123!\",\n  \"username\": \"testuser\",\n  \"fullName\": \"Test User\"\n}"
        }
      }
    }
  ]
}
```

---

**Author:** Kais OUERIEMMI  
**Version:** 1.0.0  
**Last Updated:** 2025-01-19
