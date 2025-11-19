import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import db from '../database';
import { CryptoService } from '../utils/crypto';
import jwtService from '../utils/jwt';
import emailService from '../utils/email';
import config from '../config';
import logger, { securityLogger } from '../utils/logger';

/**
 * Refresh Access Token
 * POST /api/auth/refresh-token
 */
export const refreshToken = async (req: Request, res: Response) => {
    try {
        const refreshToken = req.body.refreshToken || req.cookies?.refresh_token;

        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                error: 'NoRefreshToken',
                message: 'Refresh token not provided',
            });
        }

        // Verify refresh token
        let decoded;
        try {
            decoded = jwtService.verifyRefreshToken(refreshToken);
        } catch (error) {
            return res.status(401).json({
                success: false,
                error: 'InvalidRefreshToken',
                message: 'Invalid or expired refresh token',
            });
        }

        // Hash the token to look it up in database
        const tokenHash = CryptoService.hashToken(refreshToken);

        // Get token from database
        const tokenResult = await db.query(
            `SELECT id, user_id, token_family, revoked, is_used, replaced_by, expires_at
       FROM refresh_tokens
       WHERE token_hash = $1`,
            [tokenHash]
        );

        if (tokenResult.rows.length === 0) {
            securityLogger.logSuspiciousActivity('Refresh token not found in database', {
                userId: decoded.userId,
            });

            return res.status(401).json({
                success: false,
                error: 'InvalidRefreshToken',
                message: 'Refresh token not found',
            });
        }

        const storedToken = tokenResult.rows[0];

        // Check if token is revoked
        if (storedToken.revoked) {
            securityLogger.logSuspiciousActivity('Attempted use of revoked refresh token', {
                userId: storedToken.user_id,
                tokenId: storedToken.id,
            });

            return res.status(401).json({
                success: false,
                error: 'TokenRevoked',
                message: 'Refresh token has been revoked',
            });
        }

        // Check if token has been used (reuse detection)
        if (storedToken.is_used) {
            // Token reuse detected! Revoke entire token family
            await db.query(
                `UPDATE refresh_tokens
         SET revoked = TRUE, revoked_at = NOW(), revoked_reason = 'token_reuse_detected'
         WHERE token_family = $1`,
                [storedToken.token_family]
            );

            // Revoke all sessions for this user
            await db.query(
                'UPDATE sessions SET is_active = FALSE WHERE user_id = $1',
                [storedToken.user_id]
            );

            // Send security alert
            const userResult = await db.query('SELECT email FROM users WHERE id = $1', [storedToken.user_id]);
            if (userResult.rows.length > 0) {
                await emailService.sendSecurityAlert(
                    userResult.rows[0].email,
                    'Suspicious Activity Detected',
                    'We detected suspicious activity on your account. All your sessions have been terminated. Please change your password immediately.'
                );
            }

            securityLogger.logSuspiciousActivity('Refresh token reuse detected - revoking token family', {
                userId: storedToken.user_id,
                tokenFamily: storedToken.token_family,
            });

            return res.status(401).json({
                success: false,
                error: 'TokenReuseDetected',
                message: 'Security violation detected. All sessions have been terminated.',
            });
        }

        // Check if token is expired
        if (new Date(storedToken.expires_at) < new Date()) {
            return res.status(401).json({
                success: false,
                error: 'TokenExpired',
                message: 'Refresh token has expired',
            });
        }

        // Mark current token as used
        await db.query(
            'UPDATE refresh_tokens SET is_used = TRUE, used_at = NOW() WHERE id = $1',
            [storedToken.id]
        );

        // Get user info
        const userResult = await db.query(
            'SELECT id, email, is_active, is_locked FROM users WHERE id = $1',
            [storedToken.user_id]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].is_active || userResult.rows[0].is_locked) {
            return res.status(403).json({
                success: false,
                error: 'AccountInactive',
                message: 'Account is inactive or locked',
            });
        }

        const user = userResult.rows[0];

        // Generate new tokens
        const newAccessToken = jwtService.generateAccessToken({
            userId: user.id,
            email: user.email,
            sessionId: decoded.sessionId,
        });

        const newRefreshToken = jwtService.generateRefreshToken({
            userId: user.id,
            email: user.email,
            sessionId: decoded.sessionId,
        });

        // Store new refresh token (rotation)
        const newTokenHash = CryptoService.hashToken(newRefreshToken);
        const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        const newTokenResult = await db.query(
            `INSERT INTO refresh_tokens (user_id, token_hash, token_family, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
            [
                user.id,
                newTokenHash,
                storedToken.token_family, // Keep same family for rotation tracking
                req.ip,
                req.headers['user-agent'],
                newExpiresAt,
            ]
        );

        // Link old token to new token
        await db.query(
            'UPDATE refresh_tokens SET replaced_by = $1 WHERE id = $2',
            [newTokenResult.rows[0].id, storedToken.id]
        );

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [user.id, 'token_refreshed', 'authentication', 'info', 'Access token refreshed', req.ip, req.headers['user-agent']]
        );

        securityLogger.logAuthEvent(user.id, 'token_refreshed', true, {
            oldTokenId: storedToken.id,
            newTokenId: newTokenResult.rows[0].id,
        });

        // Set new cookies
        res.cookie('access_token', newAccessToken, {
            httpOnly: true,
            secure: config.session.cookieSecure,
            sameSite: config.session.cookieSameSite,
            maxAge: 15 * 60 * 1000,
        });

        res.cookie('refresh_token', newRefreshToken, {
            httpOnly: true,
            secure: config.session.cookieSecure,
            sameSite: config.session.cookieSameSite,
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/api/auth/refresh-token',
        });

        res.json({
            success: true,
            message: 'Token refreshed successfully',
            data: {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken,
            },
        });
    } catch (error) {
        logger.error('Refresh token error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Token refresh failed',
        });
    }
};

/**
 * Forgot Password
 * POST /api/auth/forgot-password
 */
export const forgotPassword = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        // Always return success to prevent email enumeration
        const successResponse = {
            success: true,
            message: 'If an account exists with this email, a password reset link has been sent.',
        };

        // Check if user exists
        const userResult = await db.query(
            'SELECT id, email, is_active FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].is_active) {
            // Still log the attempt
            securityLogger.logAuthEvent(null, 'password_reset_requested', false, {
                email,
                reason: 'user_not_found',
            });

            return res.json(successResponse);
        }

        const user = userResult.rows[0];

        // Generate reset token
        const resetToken = CryptoService.generateSecureToken();
        const expiresAt = new Date(Date.now() + config.security.passwordResetTokenExpiry);

        // Invalidate any existing reset tokens for this user
        await db.query(
            'UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE',
            [user.id]
        );

        // Store reset token
        await db.query(
            `INSERT INTO password_reset_tokens (user_id, token, expires_at, ip_address)
       VALUES ($1, $2, $3, $4)`,
            [user.id, resetToken, expiresAt, req.ip]
        );

        // Send reset email
        await emailService.sendPasswordResetEmail(user.email, resetToken);

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [user.id, 'password_reset_requested', 'account', 'info', 'Password reset requested', req.ip, req.headers['user-agent']]
        );

        securityLogger.logAuthEvent(user.id, 'password_reset_requested', true, {
            email: user.email,
        });

        res.json(successResponse);
    } catch (error) {
        logger.error('Forgot password error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Password reset request failed',
        });
    }
};

/**
 * Reset Password
 * POST /api/auth/reset-password
 */
export const resetPassword = async (req: Request, res: Response) => {
    try {
        const { token, newPassword } = req.body;

        // Validate new password
        const passwordValidation = PasswordService.validatePasswordComplexity(newPassword);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                error: 'WeakPassword',
                message: 'Password does not meet complexity requirements',
                errors: passwordValidation.errors,
            });
        }

        // Verify reset token
        const tokenResult = await db.query(
            `SELECT id, user_id, expires_at, used
       FROM password_reset_tokens
       WHERE token = $1`,
            [token]
        );

        if (tokenResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'InvalidToken',
                message: 'Invalid or expired reset token',
            });
        }

        const resetToken = tokenResult.rows[0];

        if (resetToken.used) {
            return res.status(400).json({
                success: false,
                error: 'TokenAlreadyUsed',
                message: 'This reset token has already been used',
            });
        }

        if (new Date(resetToken.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                error: 'TokenExpired',
                message: 'Reset token has expired',
            });
        }

        // Hash new password
        const passwordHash = await PasswordService.hash(newPassword);

        // Update password
        await db.query(
            'UPDATE users SET password_hash = $1, failed_login_attempts = 0, is_locked = FALSE, locked_until = NULL WHERE id = $2',
            [passwordHash, resetToken.user_id]
        );

        // Mark token as used
        await db.query(
            'UPDATE password_reset_tokens SET used = TRUE, used_at = NOW() WHERE id = $1',
            [resetToken.id]
        );

        // Revoke all existing sessions and refresh tokens
        await db.query(
            'UPDATE sessions SET is_active = FALSE WHERE user_id = $1',
            [resetToken.user_id]
        );

        await db.query(
            `UPDATE refresh_tokens
       SET revoked = TRUE, revoked_at = NOW(), revoked_reason = 'password_reset'
       WHERE user_id = $1`,
            [resetToken.user_id]
        );

        // Get user email for notification
        const userResult = await db.query('SELECT email FROM users WHERE id = $1', [resetToken.user_id]);

        if (userResult.rows.length > 0) {
            await emailService.sendSecurityAlert(
                userResult.rows[0].email,
                'Password Changed',
                'Your password has been successfully changed. All your sessions have been terminated for security.'
            );
        }

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [resetToken.user_id, 'password_reset', 'account', 'warning', 'Password reset completed', req.ip, req.headers['user-agent']]
        );

        securityLogger.logAuthEvent(resetToken.user_id, 'password_reset', true, {
            allSessionsRevoked: true,
        });

        res.json({
            success: true,
            message: 'Password has been reset successfully. Please log in with your new password.',
        });
    } catch (error) {
        logger.error('Reset password error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Password reset failed',
        });
    }
};

/**
 * Verify Email
 * GET /api/auth/verify-email
 */
export const verifyEmail = async (req: Request, res: Response) => {
    try {
        const { token } = req.query;

        if (!token || typeof token !== 'string') {
            return res.status(400).json({
                success: false,
                error: 'InvalidToken',
                message: 'Verification token is required',
            });
        }

        // Verify token
        const tokenResult = await db.query(
            `SELECT id, user_id, expires_at, used
       FROM email_verification_tokens
       WHERE token = $1`,
            [token]
        );

        if (tokenResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'InvalidToken',
                message: 'Invalid verification token',
            });
        }

        const verificationToken = tokenResult.rows[0];

        if (verificationToken.used) {
            return res.status(400).json({
                success: false,
                error: 'TokenAlreadyUsed',
                message: 'This verification token has already been used',
            });
        }

        if (new Date(verificationToken.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                error: 'TokenExpired',
                message: 'Verification token has expired',
            });
        }

        // Mark email as verified
        await db.query(
            'UPDATE users SET email_verified = TRUE, email_verified_at = NOW() WHERE id = $1',
            [verificationToken.user_id]
        );

        // Mark token as used
        await db.query(
            'UPDATE email_verification_tokens SET used = TRUE, used_at = NOW() WHERE id = $1',
            [verificationToken.id]
        );

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [verificationToken.user_id, 'email_verified', 'account', 'info', 'Email address verified', req.ip, req.headers['user-agent']]
        );

        securityLogger.logAuthEvent(verificationToken.user_id, 'email_verified', true);

        res.json({
            success: true,
            message: 'Email verified successfully. You can now log in.',
        });
    } catch (error) {
        logger.error('Email verification error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Email verification failed',
        });
    }
};
