import crypto from 'crypto';

/**
 * Cryptographic utilities for secure token generation and hashing
 */

export class CryptoService {
    /**
     * Generate a cryptographically secure random token
     */
    static generateSecureToken(length: number = 32): string {
        return crypto.randomBytes(length).toString('hex');
    }

    /**
     * Generate a URL-safe random token
     */
    static generateUrlSafeToken(length: number = 32): string {
        return crypto.randomBytes(length).toString('base64url');
    }

    /**
     * Hash a token using SHA-256 (for storing refresh tokens)
     */
    static hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    /**
     * Generate a random numeric code (for MFA backup codes)
     */
    static generateNumericCode(length: number = 8): string {
        const max = Math.pow(10, length) - 1;
        const min = Math.pow(10, length - 1);
        const code = crypto.randomInt(min, max + 1);
        return code.toString().padStart(length, '0');
    }

    /**
     * Generate multiple unique backup codes
     */
    static generateBackupCodes(count: number = 10): string[] {
        const codes = new Set<string>();
        while (codes.size < count) {
            codes.add(this.generateNumericCode(8));
        }
        return Array.from(codes);
    }

    /**
     * Hash backup codes for storage
     */
    static async hashBackupCodes(codes: string[]): Promise<string[]> {
        return codes.map(code => this.hashToken(code));
    }

    /**
     * Generate a state parameter for OAuth (CSRF protection)
     */
    static generateOAuthState(): string {
        return this.generateUrlSafeToken(32);
    }

    /**
     * Generate a nonce for OpenID Connect
     */
    static generateNonce(): string {
        return this.generateUrlSafeToken(32);
    }

    /**
     * Generate PKCE code verifier (for OAuth2 PKCE flow)
     */
    static generateCodeVerifier(): string {
        return this.generateUrlSafeToken(64);
    }

    /**
     * Generate PKCE code challenge from verifier
     */
    static generateCodeChallenge(verifier: string): string {
        return crypto
            .createHash('sha256')
            .update(verifier)
            .digest('base64url');
    }

    /**
     * Constant-time string comparison (prevents timing attacks)
     */
    static constantTimeCompare(a: string, b: string): boolean {
        if (a.length !== b.length) {
            return false;
        }
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }

    /**
     * Generate a fingerprint from request metadata
     */
    static generateDeviceFingerprint(
        userAgent: string,
        ipAddress: string
    ): string {
        const data = `${userAgent}:${ipAddress}`;
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Encrypt sensitive data (for storing OAuth tokens)
     */
    static encrypt(text: string, key: string): string {
        const iv = crypto.randomBytes(16);
        const keyBuffer = crypto.scryptSync(key, 'salt', 32);
        const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    }

    /**
     * Decrypt sensitive data
     */
    static decrypt(encryptedData: string, key: string): string {
        const parts = encryptedData.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid encrypted data format');
        }

        const [ivHex, authTagHex, encrypted] = parts;
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const keyBuffer = crypto.scryptSync(key, 'salt', 32);

        const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}
