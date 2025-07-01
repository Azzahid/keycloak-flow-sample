// Frontend: Google OAuth + Keycloak Token Exchange
class GoogleKeycloakAuth {
    constructor() {
        this.googleClientId = 'YOUR_GOOGLE_CLIENT_ID';
        this.keycloakUrl = 'http://localhost:8080';
        this.keycloakRealm = 'master';
        this.keycloakClientId = 'your-app-client';
    }

    // Initialize Google OAuth
    async initGoogleAuth() {
        return new Promise((resolve) => {
            gapi.load('auth2', () => {
                gapi.auth2.init({
                    client_id: this.googleClientId,
                    scope: 'openid profile email'
                }).then(() => {
                    this.googleAuth = gapi.auth2.getAuthInstance();
                    resolve();
                });
            });
        });
    }

    // Handle Google Login
    async loginWithGoogle() {
        try {
            const googleUser = await this.googleAuth.signIn();
            const googleToken = googleUser.getAuthResponse().access_token;
            const profile = googleUser.getBasicProfile();

            // Exchange Google token for Keycloak token
            const keycloakTokens = await this.exchangeGoogleTokenForKeycloak(
                googleToken, 
                profile
            );

            // Store Keycloak tokens
            localStorage.setItem('keycloak_access_token', keycloakTokens.access_token);
            localStorage.setItem('keycloak_refresh_token', keycloakTokens.refresh_token);

            return keycloakTokens;
        } catch (error) {
            console.error('Google login failed:', error);
            throw error;
        }
    }

    // Exchange Google token for Keycloak token
    async exchangeGoogleTokenForKeycloak(googleToken, profile) {
        const response = await fetch('/api/auth/google-to-keycloak', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                googleToken: googleToken,
                profile: {
                    id: profile.getId(),
                    email: profile.getEmail(),
                    name: profile.getName(),
                    imageUrl: profile.getImageUrl()
                }
            })
        });

        if (!response.ok) {
            throw new Error('Token exchange failed');
        }

        return await response.json();
    }

    // Use Keycloak token for API calls
    async callProtectedAPI(endpoint) {
        const token = localStorage.getItem('keycloak_access_token');
        
        const response = await fetch(endpoint, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.status === 401) {
            // Token expired, try to refresh
            await this.refreshKeycloakToken();
            return this.callProtectedAPI(endpoint);
        }

        return response.json();
    }

    // Refresh Keycloak token
    async refreshKeycloakToken() {
        const refreshToken = localStorage.getItem('keycloak_refresh_token');
        
        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (response.ok) {
            const tokens = await response.json();
            localStorage.setItem('keycloak_access_token', tokens.access_token);
            localStorage.setItem('keycloak_refresh_token', tokens.refresh_token);
        } else {
            // Refresh failed, redirect to login
            this.logout();
        }
    }

    // Logout
    logout() {
        localStorage.removeItem('keycloak_access_token');
        localStorage.removeItem('keycloak_refresh_token');
        this.googleAuth.signOut();
        window.location.href = '/login';
    }
}

// Usage
const auth = new GoogleKeycloakAuth();

document.getElementById('google-login-btn').addEventListener('click', async () => {
    try {
        await auth.initGoogleAuth();
        const tokens = await auth.loginWithGoogle();
        console.log('Login successful:', tokens);
        window.location.href = '/dashboard';
    } catch (error) {
        console.error('Login failed:', error);
    }
}); 