import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import config from '../config';
import logger from './logger';

export interface TokenPayload {
    userId: string;
    email: string;
    type: 'access' | 'refresh';
    sessionId?: string;
    roles?: string[];
}

export interface DecodedToken extends TokenPayload {
    iat: number;
    exp: number;
    iss: string;
    aud: string;
}

class JWTService {
    private accessTokenPrivateKey: string;
    private accessTokenPublicKey: string;
    private refreshTokenPrivateKey: string;
    private refreshTokenPublicKey: string;

    constructor() {
        try {
            // Load RSA keys
            this.accessTokenPrivateKey = fs.readFileSync(
                path.resolve(config.jwt.accessToken.privateKeyPath),
                'utf8'
            );
            this.accessTokenPublicKey = fs.readFileSync(
                path.resolve(config.jwt.accessToken.publicKeyPath),
                'utf8'
            );
            this.refreshTokenPrivateKey = fs.readFileSync(
                path.resolve(config.jwt.refreshToken.privateKeyPath),
                'utf8'
            );
            this.refreshTokenPublicKey = fs.readFileSync(
                path.resolve(config.jwt.refreshToken.publicKeyPath),
                'utf8'
            );
        } catch (error) {
            logger.error('Failed to load JWT keys', { error });
            throw new Error(
                'JWT keys not found. Please run: npm run generate:keys'
            );
        }
    }

    /**
     * Generate an access token (short-lived, 15 minutes)
     */
    generateAccessToken(payload: Omit<TokenPayload, 'type'>): string {
        const tokenPayload: TokenPayload = {
            ...payload,
            type: 'access',
        };

        return jwt.sign(tokenPayload, this.accessTokenPrivateKey, {
            algorithm: 'RS256',
            expiresIn: config.jwt.accessToken.expiry,
            issuer: 'kais-oueriemmi-auth',
            audience: 'kais-oueriemmi-api',
        });
    }

    /**
     * Generate a refresh token (long-lived, 7 days)
     */
    generateRefreshToken(payload: Omit<TokenPayload, 'type'>): string {
        const tokenPayload: TokenPayload = {
            ...payload,
            type: 'refresh',
        };

        return jwt.sign(tokenPayload, this.refreshTokenPrivateKey, {
            algorithm: 'RS256',
            expiresIn: config.jwt.refreshToken.expiry,
            issuer: 'kais-oueriemmi-auth',
            audience: 'kais-oueriemmi-api',
        });
    }

    /**
     * Verify and decode an access token
     */
    verifyAccessToken(token: string): DecodedToken {
        try {
            const decoded = jwt.verify(token, this.accessTokenPublicKey, {
                algorithms: ['RS256'],
                issuer: 'kais-oueriemmi-auth',
                audience: 'kais-oueriemmi-api',
            }) as DecodedToken;

            if (decoded.type !== 'access') {
                throw new Error('Invalid token type');
            }

            return decoded;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new Error('Access token expired');
            } else if (error instanceof jwt.JsonWebTokenError) {
                throw new Error('Invalid access token');
            }
            throw error;
        }
    }

    /**
     * Verify and decode a refresh token
     */
    verifyRefreshToken(token: string): DecodedToken {
        try {
            const decoded = jwt.verify(token, this.refreshTokenPublicKey, {
                algorithms: ['RS256'],
                issuer: 'kais-oueriemmi-auth',
                audience: 'kais-oueriemmi-api',
            }) as DecodedToken;

            if (decoded.type !== 'refresh') {
                throw new Error('Invalid token type');
            }

            return decoded;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new Error('Refresh token expired');
            } else if (error instanceof jwt.JsonWebTokenError) {
                throw new Error('Invalid refresh token');
            }
            throw error;
        }
    }

    /**
     * Decode token without verification (for debugging)
     */
    decode(token: string): DecodedToken | null {
        try {
            return jwt.decode(token) as DecodedToken;
        } catch (error) {
            return null;
        }
    }

    /**
     * Get token expiration time
     */
    getTokenExpiration(token: string): Date | null {
        const decoded = this.decode(token);
        if (decoded && decoded.exp) {
            return new Date(decoded.exp * 1000);
        }
        return null;
    }

    /**
     * Check if token is expired
     */
    isTokenExpired(token: string): boolean {
        const expiration = this.getTokenExpiration(token);
        if (!expiration) return true;
        return expiration < new Date();
    }
}

export default new JWTService();
