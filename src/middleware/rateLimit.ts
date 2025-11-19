import { Request, Response, NextFunction } from 'express';
import { RateLimiterRedis, RateLimiterRes } from 'rate-limiter-flexible';
import redisClient from '../database/redis';
import config from '../config';
import logger from '../utils/logger';

/**
 * Redis-backed rate limiting middleware using token bucket algorithm
 */

// General API rate limiter
const generalLimiter = new RateLimiterRedis({
    storeClient: redisClient.getClient(),
    keyPrefix: 'rate_limit_general',
    points: config.rateLimit.maxRequests, // Number of requests
    duration: Math.floor(config.rateLimit.windowMs / 1000), // Window in seconds
    blockDuration: 60, // Block for 1 minute if exceeded
});

// Authentication endpoints rate limiter (stricter)
const authLimiter = new RateLimiterRedis({
    storeClient: redisClient.getClient(),
    keyPrefix: 'rate_limit_auth',
    points: config.rateLimit.authMaxRequests,
    duration: Math.floor(config.rateLimit.authWindowMs / 1000),
    blockDuration: 900, // Block for 15 minutes if exceeded
});

// Password reset rate limiter (very strict)
const passwordResetLimiter = new RateLimiterRedis({
    storeClient: redisClient.getClient(),
    keyPrefix: 'rate_limit_password_reset',
    points: 3, // Only 3 attempts
    duration: 3600, // Per hour
    blockDuration: 3600, // Block for 1 hour
});

/**
 * Get client identifier (IP address or user ID if authenticated)
 */
function getClientIdentifier(req: Request): string {
    // Use user ID if authenticated, otherwise IP
    const userId = (req as any).user?.userId;
    if (userId) {
        return `user:${userId}`;
    }

    // Get IP from various headers (for proxy/load balancer support)
    const forwarded = req.headers['x-forwarded-for'] as string;
    const ip = forwarded ? forwarded.split(',')[0].trim() : req.ip || req.socket.remoteAddress || 'unknown';

    return `ip:${ip}`;
}

/**
 * Handle rate limit exceeded
 */
function handleRateLimitExceeded(
    res: Response,
    rateLimiterRes: RateLimiterRes,
    identifier: string
) {
    const retryAfter = Math.ceil(rateLimiterRes.msBeforeNext / 1000);

    logger.warn('Rate limit exceeded', {
        identifier,
        retryAfter,
    });

    res.set('Retry-After', String(retryAfter));
    res.set('X-RateLimit-Limit', String(rateLimiterRes.consumedPoints + rateLimiterRes.remainingPoints));
    res.set('X-RateLimit-Remaining', '0');
    res.set('X-RateLimit-Reset', String(Math.ceil((Date.now() + rateLimiterRes.msBeforeNext) / 1000)));

    return res.status(429).json({
        success: false,
        error: 'Too many requests',
        message: `Rate limit exceeded. Please try again in ${retryAfter} seconds.`,
        retryAfter,
    });
}

/**
 * Set rate limit headers
 */
function setRateLimitHeaders(res: Response, rateLimiterRes: RateLimiterRes) {
    res.set('X-RateLimit-Limit', String(rateLimiterRes.consumedPoints + rateLimiterRes.remainingPoints));
    res.set('X-RateLimit-Remaining', String(rateLimiterRes.remainingPoints));
    res.set('X-RateLimit-Reset', String(Math.ceil((Date.now() + rateLimiterRes.msBeforeNext) / 1000)));
}

/**
 * General rate limiting middleware
 */
export const rateLimitMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const identifier = getClientIdentifier(req);
        const rateLimiterRes = await generalLimiter.consume(identifier);

        setRateLimitHeaders(res, rateLimiterRes);
        next();
    } catch (error) {
        if (error instanceof Error) {
            return handleRateLimitExceeded(res, error as any, getClientIdentifier(req));
        }
        next(error);
    }
};

/**
 * Authentication endpoints rate limiting
 */
export const authRateLimitMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const identifier = getClientIdentifier(req);
        const rateLimiterRes = await authLimiter.consume(identifier);

        setRateLimitHeaders(res, rateLimiterRes);
        next();
    } catch (error) {
        if (error instanceof Error) {
            // Log suspicious activity
            logger.warn('Authentication rate limit exceeded', {
                identifier: getClientIdentifier(req),
                path: req.path,
                userAgent: req.headers['user-agent'],
            });

            return handleRateLimitExceeded(res, error as any, getClientIdentifier(req));
        }
        next(error);
    }
};

/**
 * Password reset rate limiting
 */
export const passwordResetRateLimitMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const email = req.body.email;
        const identifier = email ? `email:${email}` : getClientIdentifier(req);

        const rateLimiterRes = await passwordResetLimiter.consume(identifier);

        setRateLimitHeaders(res, rateLimiterRes);
        next();
    } catch (error) {
        if (error instanceof Error) {
            logger.warn('Password reset rate limit exceeded', {
                identifier: req.body.email || getClientIdentifier(req),
                ip: req.ip,
            });

            return handleRateLimitExceeded(res, error as any, getClientIdentifier(req));
        }
        next(error);
    }
};

/**
 * Custom rate limiter factory
 */
export function createRateLimiter(points: number, duration: number, blockDuration: number = 60) {
    const limiter = new RateLimiterRedis({
        storeClient: redisClient.getClient(),
        keyPrefix: `rate_limit_custom_${Date.now()}`,
        points,
        duration,
        blockDuration,
    });

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const identifier = getClientIdentifier(req);
            const rateLimiterRes = await limiter.consume(identifier);

            setRateLimitHeaders(res, rateLimiterRes);
            next();
        } catch (error) {
            if (error instanceof Error) {
                return handleRateLimitExceeded(res, error as any, getClientIdentifier(req));
            }
            next(error);
        }
    };
}
