// Simple Authorization Code Flow Approach
// This approach uses Google OAuth redirect to get auth code, then authenticates with Keycloak

class SimpleGoogleKeycloakFlow {
    constructor() {
        this.googleClientId = 'YOUR_GOOGLE_CLIENT_ID';
        this.googleClientSecret = 'YOUR_GOOGLE_CLIENT_SECRET';
        this.redirectUri = 'http://localhost:3000/auth/google/callback';
        this.keycloakUrl = 'http://localhost:8080';
        this.keycloakRealm = 'master';
        this.keycloakClientId = 'your-app-client';
    }

    // Step 1: Redirect to Google OAuth
    initiateGoogleLogin() {
        const googleAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + 
            new URLSearchParams({
                client_id: this.googleClientId,
                redirect_uri: this.redirectUri,
                response_type: 'code',
                scope: 'openid profile email',
                access_type: 'offline',
                prompt: 'consent'
            });

        window.location.href = googleAuthUrl;
    }

    // Step 2: Handle Google OAuth callback (this runs on /auth/google/callback page)
    async handleGoogleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const authCode = urlParams.get('code');
        const error = urlParams.get('error');

        if (error) {
            console.error('Google OAuth error:', error);
            window.location.href = '/login?error=google_auth_failed';
            return;
        }

        if (!authCode) {
            console.error('No authorization code received');
            window.location.href = '/login?error=no_auth_code';
            return;
        }

        try {
            // Exchange auth code for user info
            const userInfo = await this.exchangeCodeForUserInfo(authCode);
            
            // Authenticate with Keycloak using user info
            const keycloakTokens = await this.authenticateWithKeycloak(userInfo);
            
            // Store tokens and redirect to app
            localStorage.setItem('access_token', keycloakTokens.access_token);
            localStorage.setItem('refresh_token', keycloakTokens.refresh_token);
            
            window.location.href = '/dashboard';
            
        } catch (error) {
            console.error('Authentication failed:', error);
            window.location.href = '/login?error=auth_failed';
        }
    }

    // Exchange Google auth code for user information
    async exchangeCodeForUserInfo(authCode) {
        const response = await fetch('/api/auth/google/exchange', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code: authCode,
                redirect_uri: this.redirectUri
            })
        });

        if (!response.ok) {
            throw new Error('Failed to exchange code for user info');
        }

        return await response.json();
    }

    // Authenticate with Keycloak using user info
    async authenticateWithKeycloak(userInfo) {
        const response = await fetch('/api/auth/keycloak/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userInfo)
        });

        if (!response.ok) {
            throw new Error('Keycloak authentication failed');
        }

        return await response.json();
    }
}

// Backend implementation for the exchange endpoints
const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

// Exchange Google authorization code for user info
app.post('/api/auth/google/exchange', async (req, res) => {
    try {
        const { code, redirect_uri } = req.body;

        // Exchange code for access token
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: redirect_uri
        });

        const { access_token } = tokenResponse.data;

        // Get user info from Google
        const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: {
                'Authorization': `Bearer ${access_token}`
            }
        });

        res.json(userResponse.data);

    } catch (error) {
        console.error('Google token exchange failed:', error);
        res.status(400).json({ error: 'Token exchange failed' });
    }
});

// Authenticate with Keycloak using Google user info
app.post('/api/auth/keycloak/authenticate', async (req, res) => {
    try {
        const userInfo = req.body;

        // Get or create user in Keycloak
        const userId = await ensureUserExists(userInfo);

        // Generate Keycloak tokens for the user
        const tokens = await generateTokensForUser(userId, userInfo.email);

        res.json(tokens);

    } catch (error) {
        console.error('Keycloak authentication failed:', error);
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// Ensure user exists in Keycloak
async function ensureUserExists(userInfo) {
    const adminToken = await getKeycloakAdminToken();
    
    // Check if user exists
    let userId = await findUserByEmail(adminToken, userInfo.email);
    
    if (!userId) {
        // Create new user
        userId = await createKeycloakUser(adminToken, userInfo);
    } else {
        // Update existing user info
        await updateKeycloakUser(adminToken, userId, userInfo);
    }
    
    return userId;
}

// Generate tokens for user (simplified approach)
async function generateTokensForUser(userId, email) {
    // Option 1: Use direct grant with a service account approach
    const tokenUrl = `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`;
    
    const response = await axios.post(tokenUrl, new URLSearchParams({
        grant_type: 'password',
        client_id: process.env.KEYCLOAK_CLIENT_ID,
        client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
        username: email,
        password: 'EXTERNAL_OAUTH_USER', // Special password for OAuth users
        scope: 'openid profile email'
    }), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    return response.data;
}

// Usage in your login page
document.getElementById('google-login-btn').addEventListener('click', () => {
    const auth = new SimpleGoogleKeycloakFlow();
    auth.initiateGoogleLogin();
});

// Usage in your callback page (/auth/google/callback)
window.addEventListener('load', async () => {
    const auth = new SimpleGoogleKeycloakFlow();
    await auth.handleGoogleCallback();
}); 