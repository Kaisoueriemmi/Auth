import { Request, Response, NextFunction } from 'express';
import jwtService from '../utils/jwt';
import db from '../database';
import logger, { securityLogger } from '../utils/logger';

/**
 * Extend Express Request to include user data
 */
declare global {
    namespace Express {
        interface Request {
            user?: {
                userId: string;
                email: string;
                roles?: string[];
                sessionId?: string;
            };
        }
    }
}

/**
 * Authentication middleware - verify JWT access token
 */
export const authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        // Get token from Authorization header or cookie
        let token: string | undefined;

        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        } else if (req.cookies?.access_token) {
            token = req.cookies.access_token;
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized',
                message: 'No access token provided',
            });
        }

        // Verify token
        const decoded = jwtService.verifyAccessToken(token);

        // Check if user exists and is active
        const userResult = await db.query(
            'SELECT id, email, is_active, is_locked FROM users WHERE id = $1',
            [decoded.userId]
        );

        if (userResult.rows.length === 0) {
            securityLogger.logAuthEvent(
                decoded.userId,
                'token_verification_failed',
                false,
                { reason: 'user_not_found' }
            );

            return res.status(401).json({
                success: false,
                error: 'Unauthorized',
                message: 'User not found',
            });
        }

        const user = userResult.rows[0];

        if (!user.is_active) {
            securityLogger.logAuthEvent(
                user.id,
                'token_verification_failed',
                false,
                { reason: 'account_inactive' }
            );

            return res.status(403).json({
                success: false,
                error: 'Forbidden',
                message: 'Account is inactive',
            });
        }

        if (user.is_locked) {
            securityLogger.logAuthEvent(
                user.id,
                'token_verification_failed',
                false,
                { reason: 'account_locked' }
            );

            return res.status(403).json({
                success: false,
                error: 'Forbidden',
                message: 'Account is locked',
            });
        }

        // Attach user to request
        req.user = {
            userId: decoded.userId,
            email: decoded.email,
            roles: decoded.roles,
            sessionId: decoded.sessionId,
        };

        next();
    } catch (error) {
        if (error instanceof Error) {
            logger.error('Authentication error', { error: error.message });

            if (error.message.includes('expired')) {
                return res.status(401).json({
                    success: false,
                    error: 'TokenExpired',
                    message: 'Access token has expired',
                });
            }

            return res.status(401).json({
                success: false,
                error: 'Unauthorized',
                message: 'Invalid access token',
            });
        }

        next(error);
    }
};

/**
 * Optional authentication - attach user if token is valid, but don't require it
 */
export const optionalAuthenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        let token: string | undefined;

        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        } else if (req.cookies?.access_token) {
            token = req.cookies.access_token;
        }

        if (token) {
            const decoded = jwtService.verifyAccessToken(token);
            req.user = {
                userId: decoded.userId,
                email: decoded.email,
                roles: decoded.roles,
                sessionId: decoded.sessionId,
            };
        }

        next();
    } catch (error) {
        // Silently fail for optional auth
        next();
    }
};

/**
 * Authorization middleware - check if user has required role
 */
export const authorize = (...allowedRoles: string[]) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized',
                message: 'Authentication required',
            });
        }

        try {
            // Get user roles from database
            const rolesResult = await db.query(
                `SELECT r.name 
         FROM roles r
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = $1`,
                [req.user.userId]
            );

            const userRoles = rolesResult.rows.map(row => row.name);

            // Check if user has any of the allowed roles
            const hasPermission = allowedRoles.some(role => userRoles.includes(role));

            if (!hasPermission) {
                securityLogger.logAuthEvent(
                    req.user.userId,
                    'authorization_failed',
                    false,
                    {
                        requiredRoles: allowedRoles,
                        userRoles,
                        path: req.path,
                    }
                );

                return res.status(403).json({
                    success: false,
                    error: 'Forbidden',
                    message: 'Insufficient permissions',
                });
            }

            // Attach roles to request for later use
            req.user.roles = userRoles;

            next();
        } catch (error) {
            logger.error('Authorization error', { error });
            return res.status(500).json({
                success: false,
                error: 'InternalServerError',
                message: 'Authorization check failed',
            });
        }
    };
};

/**
 * Require email verification
 */
export const requireEmailVerification = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            error: 'Unauthorized',
            message: 'Authentication required',
        });
    }

    try {
        const userResult = await db.query(
            'SELECT email_verified FROM users WHERE id = $1',
            [req.user.userId]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].email_verified) {
            return res.status(403).json({
                success: false,
                error: 'EmailNotVerified',
                message: 'Please verify your email address to continue',
            });
        }

        next();
    } catch (error) {
        logger.error('Email verification check error', { error });
        next(error);
    }
};
