// Backend: Node.js/Express - Google to Keycloak Token Exchange
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'master';
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID;
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Endpoint to exchange Google token for Keycloak token
app.post('/api/auth/google-to-keycloak', async (req, res) => {
    try {
        const { googleToken, profile } = req.body;

        // Verify Google token
        const googleUser = await verifyGoogleToken(googleToken);
        
        // Create or update user in Keycloak
        const keycloakTokens = await authenticateWithKeycloak(googleUser, profile);

        res.json(keycloakTokens);
    } catch (error) {
        console.error('Token exchange failed:', error);
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// Verify Google token
async function verifyGoogleToken(token) {
    try {
        const response = await axios.get(
            `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${token}`
        );
        
        if (response.data.audience !== GOOGLE_CLIENT_ID) {
            throw new Error('Invalid audience');
        }
        
        return response.data;
    } catch (error) {
        throw new Error('Invalid Google token');
    }
}

// Authenticate with Keycloak using user info
async function authenticateWithKeycloak(googleUser, profile) {
    try {
        // Method 1: Direct Grant (if enabled in Keycloak client)
        return await directGrantAuth(profile);
        
    } catch (error) {
        // Method 2: Admin API approach (create user if not exists, then authenticate)
        return await adminApiAuth(profile);
    }
}

// Method 1: Direct Grant Authentication
async function directGrantAuth(profile) {
    const tokenUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;
    
    // Try to authenticate with email as username
    const response = await axios.post(tokenUrl, new URLSearchParams({
        grant_type: 'password',
        client_id: KEYCLOAK_CLIENT_ID,
        client_secret: KEYCLOAK_CLIENT_SECRET,
        username: profile.email,
        password: 'GOOGLE_SSO_USER', // Special marker for Google users
        scope: 'openid profile email'
    }), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    return response.data;
}

// Method 2: Admin API Authentication
async function adminApiAuth(profile) {
    // Get admin token
    const adminToken = await getKeycloakAdminToken();
    
    // Check if user exists
    let userId = await findUserByEmail(adminToken, profile.email);
    
    // Create user if doesn't exist
    if (!userId) {
        userId = await createKeycloakUser(adminToken, profile);
    }
    
    // Generate token for user (using impersonation or direct token generation)
    return await generateUserToken(adminToken, userId);
}

// Get Keycloak admin token
async function getKeycloakAdminToken() {
    const tokenUrl = `${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`;
    
    const response = await axios.post(tokenUrl, new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: 'admin-cli',
        username: 'admin',
        password: 'admin_password'
    }), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    return response.data.access_token;
}

// Find user by email
async function findUserByEmail(adminToken, email) {
    const response = await axios.get(
        `${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users?email=${email}`,
        {
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json'
            }
        }
    );

    return response.data.length > 0 ? response.data[0].id : null;
}

// Create user in Keycloak
async function createKeycloakUser(adminToken, profile) {
    const userData = {
        username: profile.email,
        email: profile.email,
        firstName: profile.name.split(' ')[0],
        lastName: profile.name.split(' ').slice(1).join(' '),
        enabled: true,
        emailVerified: true,
        attributes: {
            google_id: [profile.id],
            google_picture: [profile.imageUrl]
        }
    };

    const response = await axios.post(
        `${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users`,
        userData,
        {
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json'
            }
        }
    );

    // Extract user ID from location header
    const locationHeader = response.headers.location;
    return locationHeader.split('/').pop();
}

// Generate token for user
async function generateUserToken(adminToken, userId) {
    // Method: Use Keycloak's token exchange or impersonation
    const tokenUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;
    
    const response = await axios.post(tokenUrl, new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id: KEYCLOAK_CLIENT_ID,
        client_secret: KEYCLOAK_CLIENT_SECRET,
        subject_token: adminToken,
        requested_subject: userId,
        requested_token_type: 'urn:ietf:params:oauth:token-type:access_token'
    }), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    return response.data;
}

// Refresh Keycloak token
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refresh_token } = req.body;
        
        const tokenUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;
        
        const response = await axios.post(tokenUrl, new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: KEYCLOAK_CLIENT_ID,
            client_secret: KEYCLOAK_CLIENT_SECRET,
            refresh_token: refresh_token
        }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Token refresh failed:', error);
        res.status(401).json({ error: 'Token refresh failed' });
    }
});

// Middleware to verify Keycloak tokens
function verifyKeycloakToken(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    // Verify with Keycloak userinfo endpoint
    axios.get(`${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        req.user = response.data;
        next();
    })
    .catch(error => {
        res.status(401).json({ error: 'Invalid token' });
    });
}

// Protected route example
app.get('/api/protected', verifyKeycloakToken, (req, res) => {
    res.json({
        message: 'This is a protected route',
        user: req.user
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 