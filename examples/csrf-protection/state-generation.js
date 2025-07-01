// CSRF Protection with State Parameter

const crypto = require('crypto');

class CSRFProtection {
    constructor() {
        this.stateStore = new Map(); // In production, use Redis or database
        this.stateExpiration = 10 * 60 * 1000; // 10 minutes
    }

    // Generate secure state parameter
    generateState(sessionId, originalUrl = '/dashboard') {
        // Create cryptographically secure random state
        const randomBytes = crypto.randomBytes(32);
        const timestamp = Date.now();
        const state = crypto
            .createHash('sha256')
            .update(randomBytes + sessionId + timestamp)
            .digest('hex');

        // Store state with metadata
        const stateData = {
            sessionId: sessionId,
            originalUrl: originalUrl,
            timestamp: timestamp,
            used: false
        };

        this.stateStore.set(state, stateData);

        // Clean up expired states
        this.cleanupExpiredStates();

        return state;
    }

    // Validate state parameter
    validateState(state, sessionId) {
        const stateData = this.stateStore.get(state);

        if (!stateData) {
            throw new Error('Invalid state parameter - not found');
        }

        if (stateData.used) {
            throw new Error('State parameter already used');
        }

        if (stateData.sessionId !== sessionId) {
            throw new Error('State parameter session mismatch');
        }

        if (Date.now() - stateData.timestamp > this.stateExpiration) {
            this.stateStore.delete(state);
            throw new Error('State parameter expired');
        }

        // Mark state as used (one-time use)
        stateData.used = true;
        this.stateStore.set(state, stateData);

        return stateData;
    }

    // Clean up expired states
    cleanupExpiredStates() {
        const now = Date.now();
        for (const [state, data] of this.stateStore.entries()) {
            if (now - data.timestamp > this.stateExpiration) {
                this.stateStore.delete(state);
            }
        }
    }
}

// Frontend: Initiate Google OAuth with state
class SecureGoogleAuth {
    constructor() {
        this.csrfProtection = new CSRFProtection();
    }

    // Start secure OAuth flow
    async initiateSecureLogin(originalUrl = '/dashboard') {
        try {
            // Get session ID (from cookie or generate)
            const sessionId = this.getOrCreateSessionId();

            // Generate state parameter
            const response = await fetch('/api/auth/generate-state', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': sessionId
                },
                body: JSON.stringify({ originalUrl })
            });

            const { state } = await response.json();

            // Build Google OAuth URL with state
            const googleAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + 
                new URLSearchParams({
                    client_id: 'YOUR_GOOGLE_CLIENT_ID',
                    redirect_uri: 'http://localhost:3000/auth/google/callback',
                    response_type: 'code',
                    scope: 'openid profile email',
                    state: state, // CRITICAL: Include state parameter
                    access_type: 'offline',
                    prompt: 'consent'
                });

            window.location.href = googleAuthUrl;

        } catch (error) {
            console.error('Failed to initiate secure login:', error);
            throw error;
        }
    }

    // Get or create session ID
    getOrCreateSessionId() {
        let sessionId = localStorage.getItem('session_id');
        if (!sessionId) {
            sessionId = crypto.randomUUID();
            localStorage.setItem('session_id', sessionId);
        }
        return sessionId;
    }
}

// Backend: Generate state endpoint
app.post('/api/auth/generate-state', (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        const { originalUrl } = req.body;

        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID required' });
        }

        const csrfProtection = new CSRFProtection();
        const state = csrfProtection.generateState(sessionId, originalUrl);

        res.json({ state });

    } catch (error) {
        console.error('State generation failed:', error);
        res.status(500).json({ error: 'State generation failed' });
    }
});

// Backend: Validate state in callback
app.get('/auth/google/callback', async (req, res) => {
    try {
        const { code, state, error } = req.query;
        const sessionId = req.headers['x-session-id'] || req.cookies.session_id;

        // Check for OAuth errors
        if (error) {
            return res.redirect('/login?error=oauth_error');
        }

        // Validate required parameters
        if (!code || !state) {
            return res.redirect('/login?error=missing_parameters');
        }

        // CRITICAL: Validate state parameter
        const csrfProtection = new CSRFProtection();
        const stateData = csrfProtection.validateState(state, sessionId);

        // Continue with token exchange...
        const userInfo = await exchangeCodeForUserInfo(code);
        const keycloakTokens = await authenticateWithKeycloak(userInfo);

        // Redirect to original URL
        res.redirect(stateData.originalUrl || '/dashboard');

    } catch (error) {
        console.error('Callback validation failed:', error);
        
        if (error.message.includes('State parameter')) {
            return res.redirect('/login?error=csrf_validation_failed');
        }
        
        res.redirect('/login?error=authentication_failed');
    }
});

module.exports = { CSRFProtection, SecureGoogleAuth }; 