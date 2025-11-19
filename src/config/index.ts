import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

interface Config {
    server: {
        env: string;
        port: number;
        apiUrl: string;
        frontendUrl: string;
    };
    database: {
        host: string;
        port: number;
        name: string;
        user: string;
        password: string;
        ssl: boolean;
    };
    redis: {
        host: string;
        port: number;
        password: string;
        db: number;
    };
    jwt: {
        accessToken: {
            privateKeyPath: string;
            publicKeyPath: string;
            expiry: string;
        };
        refreshToken: {
            privateKeyPath: string;
            publicKeyPath: string;
            expiry: string;
        };
    };
    session: {
        secret: string;
        cookieDomain: string;
        cookieSecure: boolean;
        cookieSameSite: 'strict' | 'lax' | 'none';
    };
    csrf: {
        secret: string;
    };
    password: {
        minLength: number;
        requireUppercase: boolean;
        requireLowercase: boolean;
        requireNumbers: boolean;
        requireSymbols: boolean;
    };
    security: {
        maxLoginAttempts: number;
        accountLockoutDuration: number;
        passwordResetTokenExpiry: number;
        emailVerificationTokenExpiry: number;
    };
    rateLimit: {
        windowMs: number;
        maxRequests: number;
        authWindowMs: number;
        authMaxRequests: number;
    };
    oauth: {
        google: {
            clientId: string;
            clientSecret: string;
            callbackUrl: string;
        };
        github: {
            clientId: string;
            clientSecret: string;
            callbackUrl: string;
        };
    };
    email: {
        smtp: {
            host: string;
            port: number;
            secure: boolean;
            user: string;
            password: string;
        };
        from: string;
        fromName: string;
    };
    mfa: {
        issuer: string;
        backupCodesCount: number;
    };
    security_headers: {
        hstsMaxAge: number;
        cspDirectives: string;
    };
    logging: {
        level: string;
        filePath: string;
    };
    admin: {
        email: string;
        initialPassword: string;
    };
    features: {
        enableMfa: boolean;
        enableMagicLinks: boolean;
        requireEmailVerification: boolean;
        enablePasswordless: boolean;
    };
    compliance: {
        dataRetentionDays: number;
        auditLogRetentionDays: number;
    };
}

const config: Config = {
    server: {
        env: process.env.NODE_ENV || 'development',
        port: parseInt(process.env.PORT || '3000', 10),
        apiUrl: process.env.API_URL || 'http://localhost:3000',
        frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
    },
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        name: process.env.DB_NAME || 'kais_auth_db',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        ssl: process.env.DB_SSL === 'true',
    },
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379', 10),
        password: process.env.REDIS_PASSWORD || '',
        db: parseInt(process.env.REDIS_DB || '0', 10),
    },
    jwt: {
        accessToken: {
            privateKeyPath: process.env.JWT_ACCESS_TOKEN_PRIVATE_KEY_PATH || './keys/access-token-private.pem',
            publicKeyPath: process.env.JWT_ACCESS_TOKEN_PUBLIC_KEY_PATH || './keys/access-token-public.pem',
            expiry: process.env.JWT_ACCESS_TOKEN_EXPIRY || '15m',
        },
        refreshToken: {
            privateKeyPath: process.env.JWT_REFRESH_TOKEN_PRIVATE_KEY_PATH || './keys/refresh-token-private.pem',
            publicKeyPath: process.env.JWT_REFRESH_TOKEN_PUBLIC_KEY_PATH || './keys/refresh-token-public.pem',
            expiry: process.env.JWT_REFRESH_TOKEN_EXPIRY || '7d',
        },
    },
    session: {
        secret: process.env.SESSION_SECRET || 'change-this-secret',
        cookieDomain: process.env.COOKIE_DOMAIN || 'localhost',
        cookieSecure: process.env.COOKIE_SECURE === 'true',
        cookieSameSite: (process.env.COOKIE_SAME_SITE as 'strict' | 'lax' | 'none') || 'strict',
    },
    csrf: {
        secret: process.env.CSRF_SECRET || 'change-this-csrf-secret',
    },
    password: {
        minLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '12', 10),
        requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
        requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
        requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
        requireSymbols: process.env.PASSWORD_REQUIRE_SYMBOLS !== 'false',
    },
    security: {
        maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5', 10),
        accountLockoutDuration: parseInt(process.env.ACCOUNT_LOCKOUT_DURATION || '900000', 10), // 15 minutes
        passwordResetTokenExpiry: parseInt(process.env.PASSWORD_RESET_TOKEN_EXPIRY || '3600000', 10), // 1 hour
        emailVerificationTokenExpiry: parseInt(process.env.EMAIL_VERIFICATION_TOKEN_EXPIRY || '86400000', 10), // 24 hours
    },
    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
        authWindowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10),
        authMaxRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || '5', 10),
    },
    oauth: {
        google: {
            clientId: process.env.GOOGLE_CLIENT_ID || '',
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
            callbackUrl: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/api/auth/oauth/google/callback',
        },
        github: {
            clientId: process.env.GITHUB_CLIENT_ID || '',
            clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
            callbackUrl: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/api/auth/oauth/github/callback',
        },
    },
    email: {
        smtp: {
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT || '587', 10),
            secure: process.env.SMTP_SECURE === 'true',
            user: process.env.SMTP_USER || '',
            password: process.env.SMTP_PASSWORD || '',
        },
        from: process.env.EMAIL_FROM || 'noreply@kaisoueriemmi.com',
        fromName: process.env.EMAIL_FROM_NAME || 'Kais OUERIEMMI Auth System',
    },
    mfa: {
        issuer: process.env.MFA_ISSUER || 'Kais OUERIEMMI Auth',
        backupCodesCount: parseInt(process.env.MFA_BACKUP_CODES_COUNT || '10', 10),
    },
    security_headers: {
        hstsMaxAge: parseInt(process.env.HSTS_MAX_AGE || '31536000', 10),
        cspDirectives: process.env.CSP_DIRECTIVES || "default-src 'self'",
    },
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        filePath: process.env.LOG_FILE_PATH || './logs/app.log',
    },
    admin: {
        email: process.env.ADMIN_EMAIL || 'kais.oueriemmi@example.com',
        initialPassword: process.env.ADMIN_INITIAL_PASSWORD || '',
    },
    features: {
        enableMfa: process.env.ENABLE_MFA !== 'false',
        enableMagicLinks: process.env.ENABLE_MAGIC_LINKS !== 'false',
        requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION !== 'false',
        enablePasswordless: process.env.ENABLE_PASSWORDLESS !== 'false',
    },
    compliance: {
        dataRetentionDays: parseInt(process.env.DATA_RETENTION_DAYS || '365', 10),
        auditLogRetentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '730', 10),
    },
};

// Validation
if (config.server.env === 'production') {
    const requiredEnvVars = [
        'DB_PASSWORD',
        'SESSION_SECRET',
        'CSRF_SECRET',
        'SMTP_USER',
        'SMTP_PASSWORD',
    ];

    const missing = requiredEnvVars.filter(varName => !process.env[varName]);
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }

    if (config.session.secret === 'change-this-secret') {
        throw new Error('SESSION_SECRET must be changed in production');
    }
}

export default config;
