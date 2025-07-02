// Practical Examples: Authorization Code vs Access Token CSRF

// ========================================================================
// 1. AUTHORIZATION CODE CSRF - Account Linking Attack
// ========================================================================

// VULNERABLE: Authorization code callback without state protection
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query; // Could be attacker's legitimate code
    const currentUser = req.session.user; // Victim's session
    
    try {
        // This SUCCEEDS because the code is legitimate from Google
        const tokens = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                code: code, // Attacker's legitimate code
                grant_type: 'authorization_code',
                redirect_uri: 'https://yourapp.com/auth/callback'
            })
        }).then(r => r.json());
        
        // Get user profile (returns ATTACKER'S profile)
        const profile = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        }).then(r => r.json());
        
        // 🚨 VULNERABILITY: Link attacker's Google account to victim's user account
        await db.users.update(currentUser.id, {
            googleId: profile.id, // Attacker's Google ID
            googleEmail: profile.email // Attacker's email
        });
        
        res.redirect('/dashboard?linked=google');
        
    } catch (error) {
        res.redirect('/login?error=oauth_failed');
    }
});

// ATTACK RESULT:
// 1. Victim's account is now linked to attacker's Google account
// 2. Attacker can login to victim's account using "Login with Google"
// 3. Complete account takeover

// ========================================================================
// 2. ACCESS TOKEN CSRF - API Action Attack
// ========================================================================

// VULNERABLE: API endpoint without CSRF protection
app.post('/api/transfer-money', async (req, res) => {
    const { amount, to_account } = req.body;
    const authHeader = req.headers.authorization; // Bearer token
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const accessToken = authHeader.split(' ')[1]; // Victim's legitimate token
    
    try {
        // Validate token with OAuth provider
        const tokenInfo = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${accessToken}`)
            .then(r => r.json());
        
        if (tokenInfo.error) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        // Get user from token
        const user = await db.users.findByGoogleId(tokenInfo.sub);
        
        // 🚨 VULNERABILITY: No CSRF protection - any site can trigger this
        await db.transactions.create({
            from_user: user.id,
            to_account: to_account, // Attacker's account
            amount: amount,
            type: 'transfer'
        });
        
        res.json({ success: true, transaction_id: '...' });
        
    } catch (error) {
        res.status(500).json({ error: 'Transfer failed' });
    }
});

// ATTACK SCENARIO:
// 1. Victim visits attacker's malicious website
// 2. Site makes POST request to /api/transfer-money using victim's stored token
// 3. Money transferred to attacker (but victim's account not compromised)
// 4. Unauthorized action, not account takeover

// ========================================================================
// 3. SECURE IMPLEMENTATIONS
// ========================================================================

// SECURE: Authorization code with state parameter
app.get('/auth/google', (req, res) => {
    const state = crypto.randomUUID();
    const sessionData = {
        userId: req.session.user.id,
        timestamp: Date.now(),
        action: 'link_google_account'
    };
    
    // Store state server-side
    stateStore.set(state, sessionData);
    
    const oauthUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' +
        new URLSearchParams({
            client_id: process.env.GOOGLE_CLIENT_ID,
            redirect_uri: 'https://yourapp.com/auth/callback',
            response_type: 'code',
            scope: 'openid profile email',
            state: state // CSRF protection
        });
    
    res.redirect(oauthUrl);
});

app.get('/auth/callback', async (req, res) => {
    const { code, state } = req.query;
    const currentUser = req.session.user;
    
    // ✅ VALIDATE STATE PARAMETER
    const storedState = stateStore.get(state);
    
    if (!storedState) {
        return res.redirect('/login?error=invalid_state');
    }
    
    if (storedState.userId !== currentUser.id) {
        return res.redirect('/login?error=session_mismatch');
    }
    
    if (Date.now() - storedState.timestamp > 600000) { // 10 minutes
        return res.redirect('/login?error=state_expired');
    }
    
    // Mark state as used (prevent replay)
    stateStore.delete(state);
    
    // NOW it's safe to proceed with token exchange
    const tokens = await exchangeCodeForTokens(code);
    const profile = await getGoogleProfile(tokens.access_token);
    
    // Safe to link - we verified this user initiated the flow
    await linkGoogleAccount(currentUser.id, profile);
    
    res.redirect('/dashboard?linked=google');
});

// SECURE: API with CSRF protection
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/api/transfer-money', csrfProtection, async (req, res) => {
    const { amount, to_account } = req.body;
    const authHeader = req.headers.authorization;
    
    // Additional origin validation
    const origin = req.headers.origin;
    if (origin !== 'https://yourapp.com') {
        return res.status(403).json({ error: 'Invalid origin' });
    }
    
    // Validate access token
    const accessToken = authHeader.split(' ')[1];
    const tokenInfo = await validateAccessToken(accessToken);
    const user = await getUserFromToken(tokenInfo);
    
    // CSRF token automatically validated by middleware
    // Origin header validated above
    // Safe to proceed with transfer
    
    await performTransfer(user.id, to_account, amount);
    res.json({ success: true });
});

// Alternative: Use SameSite cookies for API CSRF protection
app.use(session({
    cookie: {
        sameSite: 'strict', // Blocks cross-site requests
        secure: true, // HTTPS only
        httpOnly: true // No JS access
    }
}));

// ========================================================================
// 4. KEY DIFFERENCES SUMMARY
// ========================================================================

const vulnerabilityComparison = {
    authorizationCodeCSRF: {
        target: "Account linking during OAuth flow",
        weapon: "Attacker's legitimate authorization code",
        victimContext: "Victim's session",
        result: "Account takeover - attacker can login as victim",
        prevention: ["State parameter", "PKCE", "Session validation"],
        severity: "CRITICAL - Complete account compromise"
    },
    
    accessTokenCSRF: {
        target: "API actions using OAuth tokens",
        weapon: "Victim's legitimate access token",
        attackerContext: "Attacker's malicious website",
        result: "Unauthorized actions - limited to API capabilities",
        prevention: ["CSRF tokens", "SameSite cookies", "Origin validation"],
        severity: "HIGH - Unauthorized operations"
    },
    
    keyDifference: {
        authCode: "Identity confusion - whose account gets linked",
        apiToken: "Action confusion - what action gets performed",
        analogy: {
            authCode: "Like giving someone else's hotel key to check into your room",
            apiToken: "Like someone using your credit card to make purchases"
        }
    }
};

// ========================================================================
// 5. REAL-WORLD ATTACK EXAMPLES
// ========================================================================

// Authorization Code CSRF attack URL:
const authCodeAttackUrl = 'https://yourapp.com/auth/callback?code=ATTACKERS_LEGITIMATE_CODE';
// If victim clicks this, their account gets linked to attacker's Google account

// API CSRF attack (malicious website):
const apiCSRFAttack = `
<form action="https://yourapp.com/api/transfer-money" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to_account" value="attackers_account">
    <input type="submit" value="Click for free prize!">
</form>
<script>
    // Or automatically submit
    document.forms[0].submit();
</script>
`;

module.exports = {
    vulnerabilityComparison,
    authCodeAttackUrl,
    apiCSRFAttack
}; 