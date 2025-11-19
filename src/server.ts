import app from './app';
import config from './config';
import db from './database';
import redisClient from './database/redis';
import logger from './utils/logger';

/**
 * Start the server
 */
async function startServer() {
    try {
        // Connect to Redis
        await redisClient.connect();
        logger.info('Redis connected successfully');

        // Test database connection
        const dbHealthy = await db.healthCheck();
        if (!dbHealthy) {
            throw new Error('Database connection failed');
        }
        logger.info('Database connected successfully');

        // Start HTTP server
        const server = app.listen(config.server.port, () => {
            logger.info(`🚀 Kais OUERIEMMI Auth System started`, {
                port: config.server.port,
                env: config.server.env,
                apiUrl: config.server.apiUrl,
            });

            console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 Kais OUERIEMMI Authentication System                ║
║                                                           ║
║   Server running on: ${config.server.apiUrl.padEnd(33)}║
║   Environment: ${config.server.env.padEnd(41)}║
║                                                           ║
║   Health Check: ${(config.server.apiUrl + '/health').padEnd(39)}║
║   API Docs: ${(config.server.apiUrl + '/api/docs').padEnd(43)}║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
      `);
        });

        // Graceful shutdown
        const gracefulShutdown = async (signal: string) => {
            logger.info(`${signal} received, starting graceful shutdown`);

            server.close(async () => {
                logger.info('HTTP server closed');

                try {
                    await redisClient.disconnect();
                    logger.info('Redis disconnected');

                    await db.close();
                    logger.info('Database disconnected');

                    logger.info('Graceful shutdown completed');
                    process.exit(0);
                } catch (error) {
                    logger.error('Error during shutdown', { error });
                    process.exit(1);
                }
            });

            // Force shutdown after 30 seconds
            setTimeout(() => {
                logger.error('Forced shutdown after timeout');
                process.exit(1);
            }, 30000);
        };

        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught exception', { error });
            gracefulShutdown('uncaughtException');
        });

        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled rejection', { reason, promise });
            gracefulShutdown('unhandledRejection');
        });

    } catch (error) {
        logger.error('Failed to start server', { error });
        process.exit(1);
    }
}

startServer();
