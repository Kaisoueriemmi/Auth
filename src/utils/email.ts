import nodemailer, { Transporter } from 'nodemailer';
import config from '../config';
import logger from './logger';

export interface EmailOptions {
    to: string;
    subject: string;
    html: string;
    text?: string;
}

class EmailService {
    private transporter: Transporter;

    constructor() {
        this.transporter = nodemailer.createTransport({
            host: config.email.smtp.host,
            port: config.email.smtp.port,
            secure: config.email.smtp.secure,
            auth: {
                user: config.email.smtp.user,
                pass: config.email.smtp.password,
            },
        });
    }

    /**
     * Send an email
     */
    async send(options: EmailOptions): Promise<boolean> {
        try {
            await this.transporter.sendMail({
                from: `"${config.email.fromName}" <${config.email.from}>`,
                to: options.to,
                subject: options.subject,
                html: options.html,
                text: options.text || this.stripHtml(options.html),
            });

            logger.info('Email sent successfully', {
                to: options.to,
                subject: options.subject,
            });

            return true;
        } catch (error) {
            logger.error('Failed to send email', {
                to: options.to,
                subject: options.subject,
                error,
            });
            return false;
        }
    }

    /**
     * Send email verification email
     */
    async sendVerificationEmail(email: string, token: string): Promise<boolean> {
        const verificationUrl = `${config.server.apiUrl}/api/auth/verify-email?token=${token}`;

        const html = this.getEmailTemplate(
            'Verify Your Email Address',
            `
        <p>Welcome to Kais OUERIEMMI Auth System!</p>
        <p>Please verify your email address by clicking the button below:</p>
        <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">
          Verify Email Address
        </a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="color: #6B7280; word-break: break-all;">${verificationUrl}</p>
        <p style="margin-top: 30px; color: #6B7280; font-size: 14px;">
          This link will expire in 24 hours. If you didn't create an account, please ignore this email.
        </p>
      `
        );

        return await this.send({
            to: email,
            subject: 'Verify Your Email Address',
            html,
        });
    }

    /**
     * Send password reset email
     */
    async sendPasswordResetEmail(email: string, token: string): Promise<boolean> {
        const resetUrl = `${config.server.frontendUrl}/reset-password?token=${token}`;

        const html = this.getEmailTemplate(
            'Reset Your Password',
            `
        <p>We received a request to reset your password.</p>
        <p>Click the button below to create a new password:</p>
        <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">
          Reset Password
        </a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="color: #6B7280; word-break: break-all;">${resetUrl}</p>
        <p style="margin-top: 30px; color: #6B7280; font-size: 14px;">
          This link will expire in 1 hour. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
        </p>
      `
        );

        return await this.send({
            to: email,
            subject: 'Reset Your Password',
            html,
        });
    }

    /**
     * Send magic link email (passwordless login)
     */
    async sendMagicLinkEmail(email: string, token: string): Promise<boolean> {
        const magicUrl = `${config.server.frontendUrl}/magic-login?token=${token}`;

        const html = this.getEmailTemplate(
            'Your Login Link',
            `
        <p>Click the button below to sign in to your account:</p>
        <a href="${magicUrl}" style="display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">
          Sign In
        </a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="color: #6B7280; word-break: break-all;">${magicUrl}</p>
        <p style="margin-top: 30px; color: #6B7280; font-size: 14px;">
          This link will expire in 15 minutes. If you didn't request this login link, please ignore this email.
        </p>
      `
        );

        return await this.send({
            to: email,
            subject: 'Your Login Link',
            html,
        });
    }

    /**
     * Send security alert email
     */
    async sendSecurityAlert(
        email: string,
        alertType: string,
        details: string
    ): Promise<boolean> {
        const html = this.getEmailTemplate(
            'Security Alert',
            `
        <p style="color: #DC2626; font-weight: bold;">⚠️ Security Alert</p>
        <p><strong>${alertType}</strong></p>
        <p>${details}</p>
        <p style="margin-top: 30px;">
          If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately.
        </p>
        <a href="${config.server.frontendUrl}/account/security" style="display: inline-block; padding: 12px 24px; background-color: #DC2626; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">
          Secure My Account
        </a>
      `
        );

        return await this.send({
            to: email,
            subject: `Security Alert: ${alertType}`,
            html,
        });
    }

    /**
     * Send MFA setup email
     */
    async sendMFASetupEmail(email: string): Promise<boolean> {
        const html = this.getEmailTemplate(
            'Two-Factor Authentication Enabled',
            `
        <p>✅ Two-factor authentication has been successfully enabled on your account.</p>
        <p>Your account is now more secure. You'll need to enter a verification code from your authenticator app when signing in.</p>
        <p style="margin-top: 30px; color: #6B7280; font-size: 14px;">
          If you didn't enable two-factor authentication, please contact support immediately.
        </p>
      `
        );

        return await this.send({
            to: email,
            subject: 'Two-Factor Authentication Enabled',
            html,
        });
    }

    /**
     * Email template wrapper
     */
    private getEmailTemplate(title: string, content: string): string {
        return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #F3F4F6;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #F3F4F6; padding: 40px 0;">
          <tr>
            <td align="center">
              <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="padding: 40px 40px 20px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                    <h1 style="margin: 0; color: #111827; font-size: 24px; font-weight: bold;">
                      Kais OUERIEMMI
                    </h1>
                    <p style="margin: 5px 0 0; color: #6B7280; font-size: 14px;">
                      Authentication System
                    </p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 40px; color: #374151; font-size: 16px; line-height: 1.6;">
                    ${content}
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 20px 40px; background-color: #F9FAFB; border-top: 1px solid #E5E7EB; text-align: center; border-radius: 0 0 8px 8px;">
                    <p style="margin: 0; color: #6B7280; font-size: 12px;">
                      © ${new Date().getFullYear()} Kais OUERIEMMI. All rights reserved.
                    </p>
                    <p style="margin: 10px 0 0; color: #9CA3AF; font-size: 12px;">
                      This is an automated message, please do not reply.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `;
    }

    /**
     * Strip HTML tags for plain text version
     */
    private stripHtml(html: string): string {
        return html
            .replace(/<[^>]*>/g, '')
            .replace(/\s+/g, ' ')
            .trim();
    }

    /**
     * Verify email configuration
     */
    async verifyConnection(): Promise<boolean> {
        try {
            await this.transporter.verify();
            logger.info('Email service connection verified');
            return true;
        } catch (error) {
            logger.error('Email service connection failed', { error });
            return false;
        }
    }
}

export default new EmailService();
