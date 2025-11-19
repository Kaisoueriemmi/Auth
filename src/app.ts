import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import config from './config';
import db from './database';
import redisClient from './database/redis';
import logger from './utils/logger';
import authRoutes from './routes/auth.routes';
import { rateLimitMiddleware } from './middleware/rateLimit';

const app: Express = express();

/**
 * Security Middleware
 */

// Helmet - Security headers
app.use(
    helmet({
        hsts: {
            maxAge: config.security_headers.hstsMaxAge,
            includeSubDomains: true,
            preload: true,
        },
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'https:'],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        frameguard: { action: 'deny' },
        noSniff: true,
        xssFilter: true,
    })
);

// CORS
app.use(
    cors({
        origin: config.server.frontendUrl,
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    })
);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser
app.use(cookieParser());

// CSRF Protection
const { doubleCsrfProtection, generateToken } = doubleCsrf({
    getSecret: () => config.csrf.secret,
    cookieName: 'x-csrf-token',
    cookieOptions: {
        httpOnly: true,
        secure: config.session.cookieSecure,
        sameSite: config.session.cookieSameSite,
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});

// Apply CSRF to all routes except health check
app.use((req, res, next) => {
    if (req.path === '/health' || req.path === '/api/health') {
        return next();
    }
    doubleCsrfProtection(req, res, next);
});

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
    res.json({
        success: true,
        csrfToken: generateToken(req, res),
    });
});

// Rate limiting
app.use(rateLimitMiddleware);

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('HTTP Request', {
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
        });
    });

    next();
});

/**
 * Routes
 */
app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/health', async (req: Request, res: Response) => {
    try {
        const dbHealth = await db.healthCheck();
        const redisHealth = await redisClient.healthCheck();

        const status = dbHealth && redisHealth ? 'healthy' : 'unhealthy';
        const statusCode = status === 'healthy' ? 200 : 503;

        res.status(statusCode).json({
            status,
            timestamp: new Date().toISOString(),
            services: {
                database: dbHealth ? 'up' : 'down',
                redis: redisHealth ? 'up' : 'down',
            },
            version: '1.0.0',
            author: 'Kais OUERIEMMI',
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: 'Health check failed',
        });
    }
});

// 404 handler
app.use((req: Request, res: Response) => {
    res.status(404).json({
        success: false,
        error: 'NotFound',
        message: 'The requested resource was not found',
    });
});

// Global error handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    logger.error('Unhandled error', {
        error: err,
        path: req.path,
        method: req.method,
    });

    // Don't leak error details in production
    const message = config.server.env === 'production'
        ? 'An unexpected error occurred'
        : err.message;

    res.status(err.statusCode || 500).json({
        success: false,
        error: err.name || 'InternalServerError',
        message,
        ...(config.server.env !== 'production' && { stack: err.stack }),
    });
});

export default app;
