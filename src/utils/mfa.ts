import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import config from '../config';
import { CryptoService } from './crypto';
import { PasswordService } from './password';

/**
 * Multi-Factor Authentication (MFA) Service using TOTP
 * Time-based One-Time Password (RFC 6238)
 */

export class MFAService {
    /**
     * Generate a new MFA secret for a user
     */
    static generateSecret(): string {
        return authenticator.generateSecret();
    }

    /**
     * Generate a QR code URL for authenticator apps
     */
    static async generateQRCode(
        email: string,
        secret: string
    ): Promise<string> {
        const otpauth = authenticator.keyuri(
            email,
            config.mfa.issuer,
            secret
        );

        try {
            return await QRCode.toDataURL(otpauth);
        } catch (error) {
            throw new Error('Failed to generate QR code');
        }
    }

    /**
     * Verify a TOTP code
     */
    static verifyToken(token: string, secret: string): boolean {
        try {
            return authenticator.verify({
                token,
                secret,
            });
        } catch (error) {
            return false;
        }
    }

    /**
     * Generate backup codes for MFA recovery
     */
    static generateBackupCodes(count: number = 10): string[] {
        return CryptoService.generateBackupCodes(count);
    }

    /**
     * Hash backup codes for secure storage
     */
    static async hashBackupCodes(codes: string[]): Promise<string[]> {
        return Promise.all(
            codes.map(code => PasswordService.hash(code))
        );
    }

    /**
     * Verify a backup code against hashed codes
     */
    static async verifyBackupCode(
        code: string,
        hashedCodes: string[]
    ): Promise<{ valid: boolean; usedIndex: number }> {
        for (let i = 0; i < hashedCodes.length; i++) {
            const isValid = await PasswordService.verify(hashedCodes[i], code);
            if (isValid) {
                return { valid: true, usedIndex: i };
            }
        }
        return { valid: false, usedIndex: -1 };
    }

    /**
     * Format backup codes for display (groups of 4 digits)
     */
    static formatBackupCodes(codes: string[]): string[] {
        return codes.map(code => {
            return code.match(/.{1,4}/g)?.join('-') || code;
        });
    }

    /**
     * Check if MFA setup is complete
     */
    static isSetupComplete(secret: string | null, backupCodes: string[] | null): boolean {
        return !!(secret && backupCodes && backupCodes.length > 0);
    }

    /**
     * Generate a time-based token (for testing)
     */
    static generateToken(secret: string): string {
        return authenticator.generate(secret);
    }

    /**
     * Get remaining time for current token (in seconds)
     */
    static getRemainingTime(): number {
        const epoch = Math.floor(Date.now() / 1000);
        const step = 30; // TOTP step (30 seconds)
        return step - (epoch % step);
    }
}
