import argon2 from 'argon2';
import config from '../config';

/**
 * Password hashing and verification using Argon2id
 * Argon2id is the recommended algorithm (winner of Password Hashing Competition)
 * It provides resistance against both side-channel and GPU attacks
 */

const ARGON2_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3, // 3 iterations
    parallelism: 4, // 4 threads
};

export class PasswordService {
    /**
     * Hash a password using Argon2id
     */
    static async hash(password: string): Promise<string> {
        try {
            return await argon2.hash(password, ARGON2_OPTIONS);
        } catch (error) {
            throw new Error('Failed to hash password');
        }
    }

    /**
     * Verify a password against a hash
     */
    static async verify(hash: string, password: string): Promise<boolean> {
        try {
            return await argon2.verify(hash, password);
        } catch (error) {
            return false;
        }
    }

    /**
     * Check if password needs rehashing (e.g., after changing parameters)
     */
    static async needsRehash(hash: string): Promise<boolean> {
        try {
            return argon2.needsRehash(hash, ARGON2_OPTIONS);
        } catch (error) {
            return true;
        }
    }

    /**
     * Validate password complexity
     */
    static validatePasswordComplexity(password: string): {
        valid: boolean;
        errors: string[];
    } {
        const errors: string[] = [];

        if (password.length < config.password.minLength) {
            errors.push(`Password must be at least ${config.password.minLength} characters long`);
        }

        if (config.password.requireUppercase && !/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (config.password.requireLowercase && !/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (config.password.requireNumbers && !/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        if (config.password.requireSymbols && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        // Check for common weak passwords
        const commonPasswords = [
            'password', 'password123', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567890', 'letmein', 'trustno1', 'dragon',
        ];

        if (commonPasswords.includes(password.toLowerCase())) {
            errors.push('Password is too common and easily guessable');
        }

        return {
            valid: errors.length === 0,
            errors,
        };
    }

    /**
     * Calculate password strength score (0-4)
     * 0: Very Weak, 1: Weak, 2: Fair, 3: Strong, 4: Very Strong
     */
    static calculatePasswordStrength(password: string): {
        score: number;
        feedback: string;
    } {
        let score = 0;

        // Length
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (password.length >= 16) score++;

        // Character variety
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;

        // Patterns (reduce score for common patterns)
        if (/(.)\1{2,}/.test(password)) score--; // Repeated characters
        if (/^[a-zA-Z]+$/.test(password)) score--; // Only letters
        if (/^\d+$/.test(password)) score--; // Only numbers

        // Normalize score to 0-4
        score = Math.max(0, Math.min(4, score));

        const feedback = [
            'Very Weak - Please choose a stronger password',
            'Weak - Consider adding more variety',
            'Fair - Could be stronger',
            'Strong - Good password',
            'Very Strong - Excellent password',
        ][score];

        return { score, feedback };
    }
}
