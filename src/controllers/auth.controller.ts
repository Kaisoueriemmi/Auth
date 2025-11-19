import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import db from '../database';
import { PasswordService } from '../utils/password';
import { CryptoService } from '../utils/crypto';
import jwtService from '../utils/jwt';
import emailService from '../utils/email';
import { MFAService } from '../utils/mfa';
import config from '../config';
import logger, { securityLogger } from '../utils/logger';

/**
 * User Registration
 * POST /api/auth/register
 */
export const register = async (req: Request, res: Response) => {
    try {
        const { email, password, username, fullName } = req.body;

        // Validate password complexity
        const passwordValidation = PasswordService.validatePasswordComplexity(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                error: 'WeakPassword',
                message: 'Password does not meet complexity requirements',
                errors: passwordValidation.errors,
            });
        }

        // Check if user already exists
        const existingUser = await db.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email.toLowerCase(), username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                success: false,
                error: 'UserExists',
                message: 'User with this email or username already exists',
            });
        }

        // Hash password
        const passwordHash = await PasswordService.hash(password);

        // Create user
        const userResult = await db.query(
            `INSERT INTO users (email, password_hash, username, full_name, email_verified)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, username, full_name, created_at`,
            [email.toLowerCase(), passwordHash, username, fullName, !config.features.requireEmailVerification]
        );

        const user = userResult.rows[0];

        // Assign default 'user' role
        await db.query(
            `INSERT INTO user_roles (user_id, role_id)
       SELECT $1, id FROM roles WHERE name = 'user'`,
            [user.id]
        );

        // Send verification email if required
        if (config.features.requireEmailVerification) {
            const verificationToken = CryptoService.generateSecureToken();
            const expiresAt = new Date(Date.now() + config.security.emailVerificationTokenExpiry);

            await db.query(
                `INSERT INTO email_verification_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
                [user.id, verificationToken, expiresAt]
            );

            await emailService.sendVerificationEmail(email, verificationToken);
        }

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
                user.id,
                'user_registered',
                'account',
                'info',
                'New user registration',
                req.ip,
                req.headers['user-agent'],
            ]
        );

        securityLogger.logAuthEvent(user.id, 'registration', true, {
            email: user.email,
            username: user.username,
        });

        res.status(201).json({
            success: true,
            message: config.features.requireEmailVerification
                ? 'Registration successful. Please check your email to verify your account.'
                : 'Registration successful',
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                    fullName: user.full_name,
                    emailVerified: !config.features.requireEmailVerification,
                },
            },
        });
    } catch (error) {
        logger.error('Registration error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Registration failed',
        });
    }
};

/**
 * User Login
 * POST /api/auth/login
 */
export const login = async (req: Request, res: Response) => {
    try {
        const { email, password, mfaCode } = req.body;
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'] || '';

        // Get user
        const userResult = await db.query(
            `SELECT id, email, password_hash, email_verified, is_active, is_locked, 
              locked_until, failed_login_attempts, mfa_enabled, mfa_secret, mfa_backup_codes
       FROM users WHERE email = $1`,
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
            securityLogger.logAuthEvent(null, 'login_failed', false, {
                email,
                reason: 'user_not_found',
                ip: ipAddress,
            });

            return res.status(401).json({
                success: false,
                error: 'InvalidCredentials',
                message: 'Invalid email or password',
            });
        }

        const user = userResult.rows[0];

        // Check if account is locked
        if (user.is_locked) {
            if (user.locked_until && new Date(user.locked_until) > new Date()) {
                const remainingTime = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 1000 / 60);

                securityLogger.logAuthEvent(user.id, 'login_failed', false, {
                    reason: 'account_locked',
                    remainingTime,
                });

                return res.status(403).json({
                    success: false,
                    error: 'AccountLocked',
                    message: `Account is locked. Try again in ${remainingTime} minutes.`,
                });
            } else {
                // Unlock account if lockout period has passed
                await db.query(
                    'UPDATE users SET is_locked = FALSE, locked_until = NULL, failed_login_attempts = 0 WHERE id = $1',
                    [user.id]
                );
            }
        }

        // Check if account is active
        if (!user.is_active) {
            securityLogger.logAuthEvent(user.id, 'login_failed', false, {
                reason: 'account_inactive',
            });

            return res.status(403).json({
                success: false,
                error: 'AccountInactive',
                message: 'Account is inactive',
            });
        }

        // Verify password
        const isValidPassword = await PasswordService.verify(user.password_hash, password);

        if (!isValidPassword) {
            // Increment failed login attempts
            const newAttempts = user.failed_login_attempts + 1;
            const shouldLock = newAttempts >= config.security.maxLoginAttempts;

            if (shouldLock) {
                const lockedUntil = new Date(Date.now() + config.security.accountLockoutDuration);
                await db.query(
                    `UPDATE users 
           SET failed_login_attempts = $1, is_locked = TRUE, locked_until = $2, last_failed_login = NOW()
           WHERE id = $3`,
                    [newAttempts, lockedUntil, user.id]
                );

                await emailService.sendSecurityAlert(
                    user.email,
                    'Account Locked',
                    `Your account has been locked due to ${newAttempts} failed login attempts. It will be automatically unlocked in ${config.security.accountLockoutDuration / 60000} minutes.`
                );

                securityLogger.logSuspiciousActivity('Account locked due to failed login attempts', {
                    userId: user.id,
                    attempts: newAttempts,
                    ip: ipAddress,
                });
            } else {
                await db.query(
                    'UPDATE users SET failed_login_attempts = $1, last_failed_login = NOW() WHERE id = $2',
                    [newAttempts, user.id]
                );
            }

            securityLogger.logAuthEvent(user.id, 'login_failed', false, {
                reason: 'invalid_password',
                attempts: newAttempts,
            });

            return res.status(401).json({
                success: false,
                error: 'InvalidCredentials',
                message: 'Invalid email or password',
                remainingAttempts: Math.max(0, config.security.maxLoginAttempts - newAttempts),
            });
        }

        // Check email verification
        if (config.features.requireEmailVerification && !user.email_verified) {
            return res.status(403).json({
                success: false,
                error: 'EmailNotVerified',
                message: 'Please verify your email address before logging in',
            });
        }

        // Check MFA
        if (user.mfa_enabled) {
            if (!mfaCode) {
                return res.status(200).json({
                    success: true,
                    requiresMFA: true,
                    message: 'MFA code required',
                });
            }

            // Verify MFA code
            const isValidMFA = MFAService.verifyToken(mfaCode, user.mfa_secret);

            if (!isValidMFA) {
                // Check backup codes
                if (user.mfa_backup_codes && user.mfa_backup_codes.length > 0) {
                    const backupCodeResult = await MFAService.verifyBackupCode(
                        mfaCode,
                        user.mfa_backup_codes
                    );

                    if (backupCodeResult.valid) {
                        // Remove used backup code
                        const updatedCodes = [...user.mfa_backup_codes];
                        updatedCodes.splice(backupCodeResult.usedIndex, 1);

                        await db.query(
                            'UPDATE users SET mfa_backup_codes = $1 WHERE id = $2',
                            [updatedCodes, user.id]
                        );

                        securityLogger.logAuthEvent(user.id, 'mfa_backup_code_used', true, {
                            remainingCodes: updatedCodes.length,
                        });
                    } else {
                        securityLogger.logAuthEvent(user.id, 'login_failed', false, {
                            reason: 'invalid_mfa_code',
                        });

                        return res.status(401).json({
                            success: false,
                            error: 'InvalidMFACode',
                            message: 'Invalid MFA code',
                        });
                    }
                } else {
                    securityLogger.logAuthEvent(user.id, 'login_failed', false, {
                        reason: 'invalid_mfa_code',
                    });

                    return res.status(401).json({
                        success: false,
                        error: 'InvalidMFACode',
                        message: 'Invalid MFA code',
                    });
                }
            }
        }

        // Reset failed login attempts
        await db.query(
            'UPDATE users SET failed_login_attempts = 0, last_login_at = NOW(), last_login_ip = $1, last_login_user_agent = $2 WHERE id = $3',
            [ipAddress, userAgent, user.id]
        );

        // Create session
        const sessionId = uuidv4();
        const sessionToken = CryptoService.generateSecureToken();
        const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        await db.query(
            `INSERT INTO sessions (id, user_id, session_token, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
            [sessionId, user.id, sessionToken, ipAddress, userAgent, sessionExpiresAt]
        );

        // Generate tokens
        const accessToken = jwtService.generateAccessToken({
            userId: user.id,
            email: user.email,
            sessionId,
        });

        const refreshToken = jwtService.generateRefreshToken({
            userId: user.id,
            email: user.email,
            sessionId,
        });

        // Store hashed refresh token
        const refreshTokenHash = CryptoService.hashToken(refreshToken);
        const tokenFamily = uuidv4();
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        await db.query(
            `INSERT INTO refresh_tokens (user_id, token_hash, token_family, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
            [user.id, refreshTokenHash, tokenFamily, ipAddress, userAgent, refreshExpiresAt]
        );

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [user.id, 'login_success', 'authentication', 'info', 'User logged in successfully', ipAddress, userAgent]
        );

        securityLogger.logAuthEvent(user.id, 'login_success', true, {
            sessionId,
            mfaUsed: user.mfa_enabled,
        });

        // Set cookies
        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: config.session.cookieSecure,
            sameSite: config.session.cookieSameSite,
            maxAge: 15 * 60 * 1000, // 15 minutes
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: config.session.cookieSecure,
            sameSite: config.session.cookieSameSite,
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/api/auth/refresh-token',
        });

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                accessToken,
                refreshToken,
                user: {
                    id: user.id,
                    email: user.email,
                    emailVerified: user.email_verified,
                },
            },
        });
    } catch (error) {
        logger.error('Login error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Login failed',
        });
    }
};

/**
 * User Logout
 * POST /api/auth/logout
 */
export const logout = async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        const sessionId = req.user?.sessionId;

        if (userId && sessionId) {
            // Invalidate session
            await db.query(
                'UPDATE sessions SET is_active = FALSE WHERE id = $1 AND user_id = $2',
                [sessionId, userId]
            );

            // Revoke refresh tokens for this session
            await db.query(
                `UPDATE refresh_tokens 
         SET revoked = TRUE, revoked_at = NOW(), revoked_reason = 'user_logout'
         WHERE user_id = $1`,
                [userId]
            );

            // Log audit event
            await db.query(
                `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [userId, 'logout', 'authentication', 'info', 'User logged out', req.ip, req.headers['user-agent']]
            );

            securityLogger.logAuthEvent(userId, 'logout', true, { sessionId });
        }

        // Clear cookies
        res.clearCookie('access_token');
        res.clearCookie('refresh_token', { path: '/api/auth/refresh-token' });

        res.json({
            success: true,
            message: 'Logout successful',
        });
    } catch (error) {
        logger.error('Logout error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Logout failed',
        });
    }
};
