import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import passport from '../config/passport';
import db from '../database';
import { CryptoService } from '../utils/crypto';
import jwtService from '../utils/jwt';
import config from '../config';
import logger, { securityLogger } from '../utils/logger';

/**
 * Initiate OAuth flow
 * GET /api/auth/oauth/:provider
 */
export const initiateOAuth = (provider: 'google' | 'github') => {
    return (req: Request, res: Response, next: Function) => {
        // Generate and store state for CSRF protection
        const state = CryptoService.generateOAuthState();
        res.cookie('oauth_state', state, {
            httpOnly: true,
            secure: config.session.cookieSecure,
            sameSite: config.session.cookieSameSite,
            maxAge: 10 * 60 * 1000, // 10 minutes
        });

        passport.authenticate(provider, {
            state,
            session: false,
        })(req, res, next);
    };
};

/**
 * OAuth callback
 * GET /api/auth/oauth/:provider/callback
 */
export const oauthCallback = (provider: 'google' | 'github') => {
    return async (req: Request, res: Response, next: Function) => {
        // Verify state parameter
        const receivedState = req.query.state;
        const storedState = req.cookies?.oauth_state;

        if (!receivedState || receivedState !== storedState) {
            securityLogger.logSuspiciousActivity('OAuth state mismatch', {
                provider,
                receivedState,
                ip: req.ip,
            });

            return res.redirect(`${config.server.frontendUrl}/login?error=oauth_state_mismatch`);
        }

        // Clear state cookie
        res.clearCookie('oauth_state');

        passport.authenticate(provider, { session: false }, async (err: any, user: any, info: any) => {
            try {
                if (err || !user) {
                    logger.error('OAuth authentication failed', { provider, error: err, info });
                    return res.redirect(`${config.server.frontendUrl}/login?error=oauth_failed`);
                }

                // Check if account is active
                if (!user.is_active || user.is_locked) {
                    return res.redirect(`${config.server.frontendUrl}/login?error=account_inactive`);
                }

                // Create session
                const sessionId = uuidv4();
                const sessionToken = CryptoService.generateSecureToken();
                const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

                await db.query(
                    `INSERT INTO sessions (id, user_id, session_token, ip_address, user_agent, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6)`,
                    [sessionId, user.id, sessionToken, req.ip, req.headers['user-agent'], sessionExpiresAt]
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
                    [user.id, refreshTokenHash, tokenFamily, req.ip, req.headers['user-agent'], refreshExpiresAt]
                );

                // Update last login
                await db.query(
                    'UPDATE users SET last_login_at = NOW(), last_login_ip = $1, last_login_user_agent = $2 WHERE id = $3',
                    [req.ip, req.headers['user-agent'], user.id]
                );

                // Log audit event
                await db.query(
                    `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, metadata, ip_address, user_agent)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                    [
                        user.id,
                        'oauth_login',
                        'authentication',
                        'info',
                        `User logged in via ${provider}`,
                        JSON.stringify({ provider }),
                        req.ip,
                        req.headers['user-agent'],
                    ]
                );

                securityLogger.logAuthEvent(user.id, 'oauth_login', true, {
                    provider,
                    sessionId,
                });

                // Set cookies
                res.cookie('access_token', accessToken, {
                    httpOnly: true,
                    secure: config.session.cookieSecure,
                    sameSite: config.session.cookieSameSite,
                    maxAge: 15 * 60 * 1000,
                });

                res.cookie('refresh_token', refreshToken, {
                    httpOnly: true,
                    secure: config.session.cookieSecure,
                    sameSite: config.session.cookieSameSite,
                    maxAge: 7 * 24 * 60 * 60 * 1000,
                    path: '/api/auth/refresh-token',
                });

                // Redirect to frontend with success
                res.redirect(`${config.server.frontendUrl}/dashboard?oauth=success`);
            } catch (error) {
                logger.error('OAuth callback error', { provider, error });
                res.redirect(`${config.server.frontendUrl}/login?error=oauth_error`);
            }
        })(req, res, next);
    };
};

/**
 * Link OAuth provider to existing account
 * POST /api/auth/link-provider
 */
export const linkProvider = async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { provider, providerUserId, accessToken, refreshToken, profileData } = req.body;

        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized',
                message: 'Authentication required',
            });
        }

        // Check if provider is already linked to another account
        const existingLink = await db.query(
            'SELECT user_id FROM oauth_identities WHERE provider = $1 AND provider_user_id = $2',
            [provider, providerUserId]
        );

        if (existingLink.rows.length > 0 && existingLink.rows[0].user_id !== userId) {
            return res.status(409).json({
                success: false,
                error: 'ProviderAlreadyLinked',
                message: 'This provider account is already linked to another user',
            });
        }

        // Link provider
        await db.query(
            `INSERT INTO oauth_identities (user_id, provider, provider_user_id, access_token, refresh_token, profile_data)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (provider, provider_user_id) DO UPDATE
       SET access_token = $4, refresh_token = $5, profile_data = $6, updated_at = NOW()`,
            [userId, provider, providerUserId, accessToken, refreshToken, profileData]
        );

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, metadata, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [userId, 'provider_linked', 'account', 'info', `Linked ${provider} account`, JSON.stringify({ provider }), req.ip, req.headers['user-agent']]
        );

        securityLogger.logAccountAction(userId, 'provider_linked', { provider });

        res.json({
            success: true,
            message: `${provider} account linked successfully`,
        });
    } catch (error) {
        logger.error('Link provider error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Failed to link provider',
        });
    }
};

/**
 * Unlink OAuth provider from account
 * POST /api/auth/unlink-provider
 */
export const unlinkProvider = async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { provider } = req.body;

        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized',
                message: 'Authentication required',
            });
        }

        // Check if user has a password (prevent locking out)
        const userResult = await db.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [userId]
        );

        const hasPassword = userResult.rows[0]?.password_hash;

        // Count linked providers
        const providerCount = await db.query(
            'SELECT COUNT(*) as count FROM oauth_identities WHERE user_id = $1',
            [userId]
        );

        if (!hasPassword && parseInt(providerCount.rows[0].count) <= 1) {
            return res.status(400).json({
                success: false,
                error: 'CannotUnlink',
                message: 'Cannot unlink the only authentication method. Please set a password first.',
            });
        }

        // Unlink provider
        const result = await db.query(
            'DELETE FROM oauth_identities WHERE user_id = $1 AND provider = $2',
            [userId, provider]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({
                success: false,
                error: 'ProviderNotLinked',
                message: 'Provider is not linked to this account',
            });
        }

        // Log audit event
        await db.query(
            `INSERT INTO audit_logs (user_id, event_type, event_category, severity, description, metadata, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [userId, 'provider_unlinked', 'account', 'warning', `Unlinked ${provider} account`, JSON.stringify({ provider }), req.ip, req.headers['user-agent']]
        );

        securityLogger.logAccountAction(userId, 'provider_unlinked', { provider });

        res.json({
            success: true,
            message: `${provider} account unlinked successfully`,
        });
    } catch (error) {
        logger.error('Unlink provider error', { error });
        res.status(500).json({
            success: false,
            error: 'InternalServerError',
            message: 'Failed to unlink provider',
        });
    }
};
