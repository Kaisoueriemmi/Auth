import winston from 'winston';
import path from 'path';
import fs from 'fs';
import config from '../config';

// Ensure logs directory exists
const logsDir = path.dirname(config.logging.filePath);
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for structured logging
const customFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.metadata(),
    winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let metaStr = '';
        if (Object.keys(meta).length > 0) {
            metaStr = `\n${JSON.stringify(meta, null, 2)}`;
        }
        return `${timestamp} [${level}]: ${message}${metaStr}`;
    })
);

const logger = winston.createLogger({
    level: config.logging.level,
    format: customFormat,
    defaultMeta: { service: 'kais-auth-system' },
    transports: [
        // File transport for all logs
        new winston.transports.File({
            filename: config.logging.filePath,
            maxsize: 10485760, // 10MB
            maxFiles: 5,
        }),
        // Separate file for errors
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 10485760,
            maxFiles: 5,
        }),
    ],
});

// Console transport for development
if (config.server.env !== 'production') {
    logger.add(
        new winston.transports.Console({
            format: consoleFormat,
        })
    );
}

// Security event logger
export const securityLogger = {
    logAuthEvent: (
        userId: string | null,
        eventType: string,
        success: boolean,
        metadata: Record<string, any> = {}
    ) => {
        logger.info('Security Event', {
            category: 'authentication',
            userId,
            eventType,
            success,
            ...metadata,
        });
    },

    logSuspiciousActivity: (
        description: string,
        metadata: Record<string, any> = {}
    ) => {
        logger.warn('Suspicious Activity Detected', {
            category: 'security',
            description,
            ...metadata,
        });
    },

    logAccountAction: (
        userId: string,
        action: string,
        metadata: Record<string, any> = {}
    ) => {
        logger.info('Account Action', {
            category: 'account',
            userId,
            action,
            ...metadata,
        });
    },
};

export default logger;
