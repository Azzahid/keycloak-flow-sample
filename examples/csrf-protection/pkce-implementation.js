// PKCE Implementation for Additional CSRF Protection

const crypto = require('crypto');

class PKCEProtection {
    constructor() {
        this.challengeStore = new Map(); // In production, use Redis/database
        this.challengeExpiration = 10 * 60 * 1000; // 10 minutes
    }

    // Generate PKCE code verifier and challenge
    generatePKCE(sessionId) {
        // Generate code verifier (43-128 character string)
        const codeVerifier = crypto
            .randomBytes(64)
            .toString('base64url'); // Base64URL encoding without padding

        // Generate code challenge (SHA256 hash of verifier)
        const codeChallenge = crypto
            .createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');

        // Store verifier with session info
        const challengeData = {
            sessionId: sessionId,
            codeVerifier: codeVerifier,
            timestamp: Date.now(),
            used: false
        };

        this.challengeStore.set(codeChallenge, challengeData);

        // Clean up expired challenges
        this.cleanupExpiredChallenges();

        return {
            codeChallenge: codeChallenge,
            codeChallengeMethod: 'S256', // SHA256
            codeVerifier: codeVerifier // Store this securely on client
        };
    }

    // Validate PKCE during token exchange
    validatePKCE(codeChallenge, codeVerifier, sessionId) {
        const challengeData = this.challengeStore.get(codeChallenge);

        if (!challengeData) {
            throw new Error('Invalid PKCE challenge - not found');
        }

        if (challengeData.used) {
            throw new Error('PKCE challenge already used');
        }

        if (challengeData.sessionId !== sessionId) {
            throw new Error('PKCE challenge session mismatch');
        }

        if (Date.now() - challengeData.timestamp > this.challengeExpiration) {
            this.challengeStore.delete(codeChallenge);
            throw new Error('PKCE challenge expired');
        }

        // Verify code verifier matches challenge
        const expectedChallenge = crypto
            .createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');

        if (expectedChallenge !== codeChallenge) {
            throw new Error('PKCE verification failed - verifier mismatch');
        }

        // Mark as used
        challengeData.used = true;
        this.challengeStore.set(codeChallenge, challengeData);

        return challengeData;
    }

    // Clean up expired challenges
    cleanupExpiredChallenges() {
        const now = Date.now();
        for (const [challenge, data] of this.challengeStore.entries()) {
            if (now - data.timestamp > this.challengeExpiration) {
                this.challengeStore.delete(challenge);
            }
        }
    }
}

// Enhanced Secure Google Auth with PKCE
class EnhancedSecureGoogleAuth {
    constructor() {
        this.csrfProtection = new CSRFProtection();
        this.pkceProtection = new PKCEProtection();
    }

    // Start OAuth flow with both State and PKCE
    async initiateSecureLogin(originalUrl = '/dashboard') {
        try {
            const sessionId = this.getOrCreateSessionId();

            // Generate both State and PKCE parameters
            const response = await fetch('/api/auth/generate-oauth-params', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': sessionId
                },
                body: JSON.stringify({ originalUrl })
            });

            const { state, codeChallenge, codeChallengeMethod, codeVerifier } = 
                await response.json();

            // Store code verifier securely (in secure storage)
            sessionStorage.setItem('pkce_code_verifier', codeVerifier);

            // Build Google OAuth URL with both State and PKCE
            const googleAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + 
                new URLSearchParams({
                    client_id: 'YOUR_GOOGLE_CLIENT_ID',
                    redirect_uri: 'http://localhost:3000/auth/google/callback',
                    response_type: 'code',
                    scope: 'openid profile email',
                    state: state, // CSRF protection
                    code_challenge: codeChallenge, // PKCE protection
                    code_challenge_method: codeChallengeMethod,
                    access_type: 'offline',
                    prompt: 'consent'
                });

            window.location.href = googleAuthUrl;

        } catch (error) {
            console.error('Failed to initiate secure login:', error);
            throw error;
        }
    }

    // Handle callback with enhanced validation
    async handleSecureCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const authCode = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');

        if (error) {
            throw new Error(`OAuth error: ${error}`);
        }

        if (!authCode || !state) {
            throw new Error('Missing required OAuth parameters');
        }

        // Retrieve stored PKCE verifier
        const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
        if (!codeVerifier) {
            throw new Error('PKCE code verifier not found');
        }

        // Exchange code with enhanced security
        const sessionId = this.getOrCreateSessionId();
        
        const response = await fetch('/api/auth/exchange-code-secure', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': sessionId
            },
            body: JSON.stringify({
                code: authCode,
                state: state,
                codeVerifier: codeVerifier
            })
        });

        if (!response.ok) {
            throw new Error('Secure token exchange failed');
        }

        const tokens = await response.json();

        // Clean up sensitive data
        sessionStorage.removeItem('pkce_code_verifier');

        return tokens;
    }

    getOrCreateSessionId() {
        let sessionId = localStorage.getItem('session_id');
        if (!sessionId) {
            sessionId = crypto.randomUUID();
            localStorage.setItem('session_id', sessionId);
        }
        return sessionId;
    }
}

// Backend: Generate OAuth parameters with enhanced security
app.post('/api/auth/generate-oauth-params', (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        const { originalUrl } = req.body;

        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID required' });
        }

        // Generate State parameter
        const csrfProtection = new CSRFProtection();
        const state = csrfProtection.generateState(sessionId, originalUrl);

        // Generate PKCE parameters
        const pkceProtection = new PKCEProtection();
        const pkceParams = pkceProtection.generatePKCE(sessionId);

        res.json({
            state: state,
            codeChallenge: pkceParams.codeChallenge,
            codeChallengeMethod: pkceParams.codeChallengeMethod,
            codeVerifier: pkceParams.codeVerifier // Send securely
        });

    } catch (error) {
        console.error('OAuth params generation failed:', error);
        res.status(500).json({ error: 'Parameter generation failed' });
    }
});

// Backend: Enhanced secure token exchange
app.post('/api/auth/exchange-code-secure', async (req, res) => {
    try {
        const { code, state, codeVerifier } = req.body;
        const sessionId = req.headers['x-session-id'];

        if (!code || !state || !codeVerifier || !sessionId) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        // Validate State parameter (CSRF protection)
        const csrfProtection = new CSRFProtection();
        const stateData = csrfProtection.validateState(state, sessionId);

        // Validate PKCE (additional protection)
        const pkceProtection = new PKCEProtection();
        const codeChallenge = crypto
            .createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');
        
        pkceProtection.validatePKCE(codeChallenge, codeVerifier, sessionId);

        // Exchange authorization code for access token with PKCE
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: 'http://localhost:3000/auth/google/callback',
                code_verifier: codeVerifier // Include PKCE verifier
            })
        });

        if (!tokenResponse.ok) {
            throw new Error('Token exchange failed');
        }

        const tokens = await tokenResponse.json();

        // Get user info and authenticate with Keycloak
        const userInfo = await getUserInfoFromGoogle(tokens.access_token);
        const keycloakTokens = await authenticateWithKeycloak(userInfo);

        res.json({
            access_token: keycloakTokens.access_token,
            refresh_token: keycloakTokens.refresh_token,
            redirectUrl: stateData.originalUrl
        });

    } catch (error) {
        console.error('Secure token exchange failed:', error);
        
        if (error.message.includes('State parameter') || 
            error.message.includes('PKCE')) {
            return res.status(401).json({ error: 'Security validation failed' });
        }
        
        res.status(500).json({ error: 'Authentication failed' });
    }
});

module.exports = { PKCEProtection, EnhancedSecureGoogleAuth }; 