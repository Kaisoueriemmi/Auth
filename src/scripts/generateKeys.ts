import fs from 'fs';
import path from 'path';
import { generateKeyPairSync } from 'crypto';

/**
 * Generate RSA key pairs for JWT signing (RS256)
 * Run this script once during initial setup: npm run generate:keys
 */

const keysDir = path.resolve(__dirname, '../../keys');

// Create keys directory if it doesn't exist
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
    console.log('✅ Created keys directory');
}

// Generate access token key pair
console.log('🔑 Generating access token RSA key pair...');
const accessTokenKeyPair = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    },
});

fs.writeFileSync(
    path.join(keysDir, 'access-token-private.pem'),
    accessTokenKeyPair.privateKey
);
fs.writeFileSync(
    path.join(keysDir, 'access-token-public.pem'),
    accessTokenKeyPair.publicKey
);
console.log('✅ Access token keys generated');

// Generate refresh token key pair
console.log('🔑 Generating refresh token RSA key pair...');
const refreshTokenKeyPair = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    },
});

fs.writeFileSync(
    path.join(keysDir, 'refresh-token-private.pem'),
    refreshTokenKeyPair.privateKey
);
fs.writeFileSync(
    path.join(keysDir, 'refresh-token-public.pem'),
    refreshTokenKeyPair.publicKey
);
console.log('✅ Refresh token keys generated');

console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🎉 RSA Key Pairs Generated Successfully!               ║
║                                                           ║
║   Location: ${keysDir.padEnd(42)}║
║                                                           ║
║   Files created:                                          ║
║   - access-token-private.pem                              ║
║   - access-token-public.pem                               ║
║   - refresh-token-private.pem                             ║
║   - refresh-token-public.pem                              ║
║                                                           ║
║   ⚠️  IMPORTANT: Keep private keys secure!               ║
║   Never commit these keys to version control.             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`);
