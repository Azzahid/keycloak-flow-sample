// OAuth2 CSRF Attack Explanation - Why Google's Validation Isn't Enough

// 🔥 THE FUNDAMENTAL PROBLEM:
// Authorization codes are "bearer tokens" - whoever presents them gets access
// Google validates the CODE is legitimate, but not WHO should be using it

// ========================================================================
// ATTACK STEP 1: Attacker Gets Legitimate Authorization Code
// ========================================================================

// Attacker starts normal OAuth flow
function attackerStartsOAuth() {
    // This is a completely legitimate OAuth request
    const attackerOAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + 
        new URLSearchParams({
            client_id: 'YOUR_APP_CLIENT_ID',
            redirect_uri: 'https://yourapp.com/auth/callback',
            response_type: 'code',
            scope: 'openid profile email'
            // ⚠️ NO STATE PARAMETER - this is the vulnerability
        });
    
    // Attacker visits this URL in their browser
    // Google shows login page for attacker's account
    // Attacker logs in with their Google account
    // Google redirects to: https://yourapp.com/auth/callback?code=LEGITIMATE_CODE
    
    return 'LEGITIMATE_AUTH_CODE_FROM_GOOGLE'; // Attacker captures this
}

// ========================================================================
// ATTACK STEP 2: What Google Validates vs What's Missing
// ========================================================================

// When Google issues the authorization code, they validate:
const googleValidations = {
    codeExists: true,           // ✅ Code was issued by Google
    codeNotExpired: true,       // ✅ Code is still valid (10 min window)
    clientIdMatches: true,      // ✅ Code issued for this client_id
    redirectUriMatches: true,   // ✅ Code issued for this redirect_uri
    scopesMatch: true          // ✅ Code issued for these scopes
};

// What Google DOES NOT validate:
const googleDoesNotValidate = {
    whoShouldUseCode: false,    // ❌ Google doesn't know which user session should use this code
    sessionBinding: false,      // ❌ No binding to specific user session
    requestOrigin: false,       // ❌ Code can be used from any source
    userIntent: false          // ❌ No proof that current user intended this login
};

// ========================================================================
// ATTACK STEP 3: Attacker Tricks Victim
// ========================================================================

// Attacker tricks victim into visiting URL with their legitimate code
function attackerTricksVictim(legitimateCode) {
    // Attacker sends victim this link via email, social media, etc.
    const maliciousLink = `https://yourapp.com/auth/callback?code=${legitimateCode}`;
    
    // Victim clicks link (maybe disguised as something else)
    // Victim's browser makes request with attacker's legitimate code
    // BUT in victim's session context
    
    return {
        userSession: 'VICTIM_SESSION_ID',
        authorizationCode: legitimateCode, // Attacker's legitimate code
        browserCookies: 'victim_session_cookies'
    };
}

// ========================================================================
// ATTACK STEP 4: Your App Processes the Request
// ========================================================================

// Your vulnerable callback handler (WITHOUT CSRF protection)
async function vulnerableCallbackHandler(req, res) {
    const { code } = req.query;
    const userSession = req.session; // This is VICTIM'S session
    
    // Your app exchanges the code (this SUCCEEDS because code is legitimate)
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: 'YOUR_CLIENT_ID',
            client_secret: 'YOUR_CLIENT_SECRET',
            code: code, // ATTACKER'S legitimate code
            grant_type: 'authorization_code',
            redirect_uri: 'https://yourapp.com/auth/callback'
        })
    });
    
    // Google validates and returns ATTACKER'S profile
    const tokens = await tokenResponse.json(); // ✅ SUCCESS - code was legitimate!
    
    // Get user profile
    const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    });
    
    const attackerProfile = await profileResponse.json();
    // attackerProfile = {
    //     email: "attacker@evil.com",
    //     name: "Attacker Name",
    //     id: "attacker_google_id"
    // }
    
    // 🚨 CRITICAL VULNERABILITY: 
    // You link attacker's Google account to victim's session
    await linkGoogleAccountToUser(userSession.userId, attackerProfile);
    
    // Victim gets logged in successfully (they don't notice anything wrong)
    res.redirect('/dashboard');
}

// ========================================================================
// ATTACK RESULT: Account Takeover
// ========================================================================

// Later, attacker can access victim's account
async function attackerAccessesVictimAccount() {
    // Attacker goes to your app and clicks "Login with Google"
    // Uses their own Google account (attacker@evil.com)
    // Your app finds the linked account and logs attacker into VICTIM'S account
    
    const attackerGoogleProfile = {
        email: "attacker@evil.com",
        id: "attacker_google_id"
    };
    
    // Your app looks up: which user account is linked to this Google ID?
    const linkedAccount = await findUserByGoogleId(attackerGoogleProfile.id);
    // Returns: VICTIM'S user account (because of the CSRF attack)
    
    // Attacker now has full access to victim's account
    return loginUser(linkedAccount.userId); // VICTIM'S account!
}

// ========================================================================
// WHY GOOGLE'S VALIDATION ALONE ISN'T ENOUGH
// ========================================================================

const whyGoogleValidationFails = {
    problem: "Authorization codes are bearer tokens",
    explanation: [
        "Google validates the code is legitimate and not expired",
        "Google validates the code belongs to the correct client",
        "But Google has NO WAY to know which user session should use the code",
        "The code is like a concert ticket - valid, but doesn't specify who should use it",
        "Anyone who has the code can use it within the expiration window"
    ],
    
    analogy: "It's like a hotel room key that works, but doesn't check if you're the person who made the reservation",
    
    coreIssue: "Lack of binding between authorization code and specific user session"
};

// ========================================================================
// HOW STATE PARAMETER PREVENTS THIS ATTACK
// ========================================================================

async function secureCallbackHandler(req, res) {
    const { code, state } = req.query;
    const userSession = req.session;
    
    // ✅ CSRF PROTECTION: Validate state parameter
    const storedStateData = await getStoredState(state);
    
    if (!storedStateData) {
        throw new Error('Invalid state parameter - CSRF attack detected');
    }
    
    if (storedStateData.sessionId !== userSession.id) {
        throw new Error('State parameter session mismatch - CSRF attack detected');
    }
    
    if (storedStateData.used) {
        throw new Error('State parameter already used - replay attack detected');
    }
    
    if (Date.now() - storedStateData.timestamp > 600000) { // 10 minutes
        throw new Error('State parameter expired');
    }
    
    // Mark state as used
    await markStateAsUsed(state);
    
    // NOW it's safe to proceed with token exchange
    // We know this code exchange was initiated by THIS user session
    const tokens = await exchangeCodeForTokens(code);
    const profile = await getUserProfile(tokens.access_token);
    
    // Safe to link account - we verified the user intended this action
    await linkGoogleAccountToUser(userSession.userId, profile);
    
    res.redirect('/dashboard');
}

// ========================================================================
// THE KEY INSIGHT
// ========================================================================

const keyInsight = {
    attackDoesNotInvolve: [
        "Forging authorization codes",
        "Breaking Google's validation",
        "Intercepting network traffic",
        "Exploiting Google's OAuth implementation"
    ],
    
    attackInvolves: [
        "Using a LEGITIMATE authorization code",
        "In the WRONG user session context",
        "Tricking user into processing attacker's legitimate code",
        "Exploiting lack of session binding"
    ],
    
    solution: [
        "State parameter binds code exchange to specific session",
        "PKCE provides additional verification",
        "Session validation ensures user initiated the flow",
        "Origin checking prevents cross-site requests"
    ]
};

module.exports = {
    attackerStartsOAuth,
    vulnerableCallbackHandler,
    secureCallbackHandler,
    whyGoogleValidationFails,
    keyInsight
}; 