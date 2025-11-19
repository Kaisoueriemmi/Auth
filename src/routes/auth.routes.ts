import { Router } from 'express';
import { body, query } from 'express-validator';
import { validate } from '../middleware/validation';
import { authenticate, authorize, requireEmailVerification } from '../middleware/auth';
import { authRateLimitMiddleware, passwordResetRateLimitMiddleware } from '../middleware/rateLimit';
import * as authController from '../controllers/auth.controller';
import * as tokenController from '../controllers/token.controller';
import * as oauthController from '../controllers/oauth.controller';

const router = Router();

/**
 * Authentication Routes
 */

// Register
router.post(
    '/register',
    authRateLimitMiddleware,
    [
        body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
        body('password').isLength({ min: 12 }).withMessage('Password must be at least 12 characters'),
        body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must be 3-30 alphanumeric characters'),
        body('fullName').optional().isLength({ max: 255 }),
    ],
    validate,
    authController.register
);

// Login
router.post(
    '/login',
    authRateLimitMiddleware,
    [
        body('email').isEmail().normalizeEmail(),
        body('password').notEmpty(),
        body('mfaCode').optional().isLength({ min: 6, max: 8 }),
    ],
    validate,
    authController.login
);

// Logout
router.post('/logout', authenticate, authController.logout);

// Refresh token
router.post(
    '/refresh-token',
    [body('refreshToken').optional().isString()],
    validate,
    tokenController.refreshToken
);

// Forgot password
router.post(
    '/forgot-password',
    passwordResetRateLimitMiddleware,
    [body('email').isEmail().normalizeEmail()],
    validate,
    tokenController.forgotPassword
);

// Reset password
router.post(
    '/reset-password',
    [
        body('token').notEmpty(),
        body('newPassword').isLength({ min: 12 }),
    ],
    validate,
    tokenController.resetPassword
);

// Verify email
router.get(
    '/verify-email',
    [query('token').notEmpty()],
    validate,
    tokenController.verifyEmail
);

/**
 * OAuth Routes
 */

// Google OAuth
router.get('/oauth/google', oauthController.initiateOAuth('google'));
router.get('/oauth/google/callback', oauthController.oauthCallback('google'));

// GitHub OAuth
router.get('/oauth/github', oauthController.initiateOAuth('github'));
router.get('/oauth/github/callback', oauthController.oauthCallback('github'));

// Link provider
router.post(
    '/link-provider',
    authenticate,
    requireEmailVerification,
    [
        body('provider').isIn(['google', 'github']),
        body('providerUserId').notEmpty(),
    ],
    validate,
    oauthController.linkProvider
);

// Unlink provider
router.post(
    '/unlink-provider',
    authenticate,
    requireEmailVerification,
    [body('provider').isIn(['google', 'github'])],
    validate,
    oauthController.unlinkProvider
);

/**
 * Session Management Routes
 */

// Get all sessions
router.get('/sessions', authenticate, async (req, res) => {
    try {
        const result = await require('../database').default.query(
            `SELECT id, device_name, device_type, ip_address, created_at, last_activity, expires_at
       FROM sessions
       WHERE user_id = $1 AND is_active = TRUE AND expires_at > NOW()
       ORDER BY last_activity DESC`,
            [req.user?.userId]
        );

        res.json({
            success: true,
            data: { sessions: result.rows },
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch sessions' });
    }
});

// Delete specific session
router.delete('/sessions/:id', authenticate, async (req, res) => {
    try {
        await require('../database').default.query(
            'UPDATE sessions SET is_active = FALSE WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user?.userId]
        );

        res.json({ success: true, message: 'Session terminated' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to terminate session' });
    }
});

/**
 * Admin Routes
 */

// Get user roles (admin only)
router.get(
    '/users/:id/roles',
    authenticate,
    authorize('admin'),
    async (req, res) => {
        try {
            const result = await require('../database').default.query(
                `SELECT r.name, r.description, ur.assigned_at
         FROM roles r
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = $1`,
                [req.params.id]
            );

            res.json({
                success: true,
                data: { roles: result.rows },
            });
        } catch (error) {
            res.status(500).json({ success: false, error: 'Failed to fetch user roles' });
        }
    }
);

export default router;
