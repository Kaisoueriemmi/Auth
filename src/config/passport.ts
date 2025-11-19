import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import config from '../config';
import db from '../database';
import logger from '../utils/logger';

/**
 * Configure Passport OAuth strategies
 */

// Google OAuth2 Strategy
if (config.oauth.google.clientId && config.oauth.google.clientSecret) {
    passport.use(
        new GoogleStrategy(
            {
                clientID: config.oauth.google.clientId,
                clientSecret: config.oauth.google.clientSecret,
                callbackURL: config.oauth.google.callbackUrl,
                scope: ['openid', 'email', 'profile'],
            },
            async (accessToken, refreshToken, profile, done) => {
                try {
                    const email = profile.emails?.[0]?.value;
                    if (!email) {
                        return done(new Error('No email found in Google profile'));
                    }

                    // Check if OAuth identity exists
                    let identityResult = await db.query(
                        'SELECT user_id FROM oauth_identities WHERE provider = $1 AND provider_user_id = $2',
                        ['google', profile.id]
                    );

                    let userId: string;

                    if (identityResult.rows.length > 0) {
                        // Existing OAuth identity
                        userId = identityResult.rows[0].user_id;

                        // Update OAuth identity
                        await db.query(
                            `UPDATE oauth_identities
               SET access_token = $1, refresh_token = $2, profile_data = $3, updated_at = NOW()
               WHERE provider = $4 AND provider_user_id = $5`,
                            [accessToken, refreshToken, JSON.stringify(profile._json), 'google', profile.id]
                        );
                    } else {
                        // Check if user exists with this email
                        const userResult = await db.query(
                            'SELECT id FROM users WHERE email = $1',
                            [email.toLowerCase()]
                        );

                        if (userResult.rows.length > 0) {
                            // Link to existing user
                            userId = userResult.rows[0].id;
                        } else {
                            // Create new user
                            const newUserResult = await db.query(
                                `INSERT INTO users (email, email_verified, full_name)
                 VALUES ($1, TRUE, $2)
                 RETURNING id`,
                                [email.toLowerCase(), profile.displayName]
                            );

                            userId = newUserResult.rows[0].id;

                            // Assign default role
                            await db.query(
                                `INSERT INTO user_roles (user_id, role_id)
                 SELECT $1, id FROM roles WHERE name = 'user'`,
                                [userId]
                            );
                        }

                        // Create OAuth identity
                        await db.query(
                            `INSERT INTO oauth_identities (user_id, provider, provider_user_id, provider_email, access_token, refresh_token, profile_data)
               VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                            [userId, 'google', profile.id, email, accessToken, refreshToken, JSON.stringify(profile._json)]
                        );
                    }

                    // Get user data
                    const user = await db.query(
                        'SELECT id, email, is_active, is_locked FROM users WHERE id = $1',
                        [userId]
                    );

                    return done(null, user.rows[0]);
                } catch (error) {
                    logger.error('Google OAuth error', { error });
                    return done(error);
                }
            }
        )
    );
}

// GitHub OAuth2 Strategy
if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
    passport.use(
        new GitHubStrategy(
            {
                clientID: config.oauth.github.clientId,
                clientSecret: config.oauth.github.clientSecret,
                callbackURL: config.oauth.github.callbackUrl,
                scope: ['user:email'],
            },
            async (accessToken: string, refreshToken: string, profile: any, done: any) => {
                try {
                    // GitHub may return multiple emails, find the primary verified one
                    const primaryEmail = profile.emails?.find((e: any) => e.primary && e.verified);
                    const email = primaryEmail?.value || profile.emails?.[0]?.value;

                    if (!email) {
                        return done(new Error('No email found in GitHub profile'));
                    }

                    // Check if OAuth identity exists
                    let identityResult = await db.query(
                        'SELECT user_id FROM oauth_identities WHERE provider = $1 AND provider_user_id = $2',
                        ['github', profile.id]
                    );

                    let userId: string;

                    if (identityResult.rows.length > 0) {
                        // Existing OAuth identity
                        userId = identityResult.rows[0].user_id;

                        // Update OAuth identity
                        await db.query(
                            `UPDATE oauth_identities
               SET access_token = $1, provider_username = $2, profile_data = $3, updated_at = NOW()
               WHERE provider = $4 AND provider_user_id = $5`,
                            [accessToken, profile.username, JSON.stringify(profile._json), 'github', profile.id]
                        );
                    } else {
                        // Check if user exists with this email
                        const userResult = await db.query(
                            'SELECT id FROM users WHERE email = $1',
                            [email.toLowerCase()]
                        );

                        if (userResult.rows.length > 0) {
                            // Link to existing user
                            userId = userResult.rows[0].id;
                        } else {
                            // Create new user
                            const newUserResult = await db.query(
                                `INSERT INTO users (email, email_verified, username, full_name)
                 VALUES ($1, TRUE, $2, $3)
                 RETURNING id`,
                                [email.toLowerCase(), profile.username, profile.displayName || profile.username]
                            );

                            userId = newUserResult.rows[0].id;

                            // Assign default role
                            await db.query(
                                `INSERT INTO user_roles (user_id, role_id)
                 SELECT $1, id FROM roles WHERE name = 'user'`,
                                [userId]
                            );
                        }

                        // Create OAuth identity
                        await db.query(
                            `INSERT INTO oauth_identities (user_id, provider, provider_user_id, provider_email, provider_username, access_token, profile_data)
               VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                            [userId, 'github', profile.id, email, profile.username, accessToken, JSON.stringify(profile._json)]
                        );
                    }

                    // Get user data
                    const user = await db.query(
                        'SELECT id, email, is_active, is_locked FROM users WHERE id = $1',
                        [userId]
                    );

                    return done(null, user.rows[0]);
                } catch (error) {
                    logger.error('GitHub OAuth error', { error });
                    return done(error);
                }
            }
        )
    );
}

export default passport;
