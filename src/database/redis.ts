import { createClient, RedisClientType } from 'redis';
import config from '../config';
import logger from '../utils/logger';

class RedisClient {
    private client: RedisClientType;
    private static instance: RedisClient;

    private constructor() {
        this.client = createClient({
            socket: {
                host: config.redis.host,
                port: config.redis.port,
            },
            password: config.redis.password || undefined,
            database: config.redis.db,
        });

        this.client.on('error', (err) => {
            logger.error('Redis client error', { error: err });
        });

        this.client.on('connect', () => {
            logger.info('Redis client connected');
        });

        this.client.on('ready', () => {
            logger.info('Redis client ready');
        });
    }

    public static getInstance(): RedisClient {
        if (!RedisClient.instance) {
            RedisClient.instance = new RedisClient();
        }
        return RedisClient.instance;
    }

    public async connect(): Promise<void> {
        if (!this.client.isOpen) {
            await this.client.connect();
        }
    }

    public async disconnect(): Promise<void> {
        if (this.client.isOpen) {
            await this.client.quit();
        }
    }

    public getClient(): RedisClientType {
        return this.client;
    }

    // Rate limiting helper
    public async incrementRateLimit(key: string, windowMs: number): Promise<number> {
        const count = await this.client.incr(key);
        if (count === 1) {
            await this.client.pExpire(key, windowMs);
        }
        return count;
    }

    // Token bucket rate limiting
    public async checkRateLimit(
        identifier: string,
        maxRequests: number,
        windowMs: number
    ): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
        const key = `rate_limit:${identifier}`;
        const now = Date.now();
        const windowStart = now - windowMs;

        // Remove old entries
        await this.client.zRemRangeByScore(key, 0, windowStart);

        // Count requests in current window
        const count = await this.client.zCard(key);

        if (count >= maxRequests) {
            const oldestEntry = await this.client.zRange(key, 0, 0, { REV: false });
            const resetAt = oldestEntry.length > 0 ? parseInt(oldestEntry[0]) + windowMs : now + windowMs;

            return {
                allowed: false,
                remaining: 0,
                resetAt,
            };
        }

        // Add current request
        await this.client.zAdd(key, { score: now, value: `${now}` });
        await this.client.pExpire(key, windowMs);

        return {
            allowed: true,
            remaining: maxRequests - count - 1,
            resetAt: now + windowMs,
        };
    }

    // Session management
    public async setSession(sessionId: string, data: any, expirySeconds: number): Promise<void> {
        await this.client.setEx(`session:${sessionId}`, expirySeconds, JSON.stringify(data));
    }

    public async getSession(sessionId: string): Promise<any | null> {
        const data = await this.client.get(`session:${sessionId}`);
        return data ? JSON.parse(data) : null;
    }

    public async deleteSession(sessionId: string): Promise<void> {
        await this.client.del(`session:${sessionId}`);
    }

    // Cache helpers
    public async set(key: string, value: string, expirySeconds?: number): Promise<void> {
        if (expirySeconds) {
            await this.client.setEx(key, expirySeconds, value);
        } else {
            await this.client.set(key, value);
        }
    }

    public async get(key: string): Promise<string | null> {
        return await this.client.get(key);
    }

    public async del(key: string): Promise<void> {
        await this.client.del(key);
    }

    public async exists(key: string): Promise<boolean> {
        return (await this.client.exists(key)) === 1;
    }

    // Health check
    public async healthCheck(): Promise<boolean> {
        try {
            await this.client.ping();
            return true;
        } catch (error) {
            logger.error('Redis health check failed', { error });
            return false;
        }
    }
}

export default RedisClient.getInstance();
