# OAuth2 Token Types & CSRF Vulnerabilities Comparison

## 🎯 **Quick Answer**

**Authorization Code CSRF** is specifically about **account linking** during login flow.  
**Access Token** usage has different vulnerabilities, but the classic "authorization code CSRF" doesn't apply the same way.

## 📊 **Token Types & Their CSRF Exposure**

| Token Type | CSRF Risk | Attack Vector | Impact |
|------------|-----------|---------------|---------|
| **Authorization Code** | 🔴 **HIGH** | Account linking CSRF | Account takeover |
| **Access Token (Implicit)** | 🔴 **HIGH** | Token injection/stealing | Account takeover |
| **Access Token (API usage)** | 🟡 **MEDIUM** | API CSRF (if no CSRF protection) | Unauthorized actions |
| **Refresh Token** | 🟢 **LOW** | Rarely exposed to CSRF | N/A |

## 🔍 **Detailed Analysis**

### **1. Authorization Code CSRF (The Classic Attack)**

**🎯 Target:** Account linking during login flow  
**⚔️ Weapon:** Legitimate authorization code used in wrong session  
**💥 Impact:** Complete account takeover

```javascript
// Vulnerable authorization code handling
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query; // Attacker's legitimate code
    const userSession = req.session; // Victim's session
    
    // Exchange code for tokens (SUCCEEDS - code is legitimate!)
    const tokens = await exchangeCodeForTokens(code);
    const profile = await getGoogleProfile(tokens.access_token);
    
    // 🚨 VULNERABILITY: Link attacker's Google account to victim's user account
    await linkGoogleAccount(userSession.userId, profile.id);
    
    res.redirect('/dashboard'); // Victim logged in, attack complete
});
```

**Why this works:**
- Code is **legitimate** (Google validates successfully)
- Code exchange happens in **victim's session context** 
- Victim's account gets linked to **attacker's Google account**
- Later, attacker logs in with Google → gets access to victim's account

---

### **2. Access Token (Implicit Flow) CSRF**

**🎯 Target:** Direct token stealing/injection  
**⚔️ Weapon:** Token in URL fragment  
**💥 Impact:** Account takeover + token theft

```javascript
// Implicit flow - tokens in URL fragment (DEPRECATED for this reason)
// https://yourapp.com/#access_token=ya29.attacker_token&token_type=Bearer

// Vulnerable implicit flow handling
function handleImplicitFlow() {
    const urlParams = new URLSearchParams(window.location.hash.substring(1));
    const accessToken = urlParams.get('access_token'); // Could be attacker's token!
    
    // If attacker tricks victim to visit URL with attacker's token:
    // Victim's session gets attacker's token
    localStorage.setItem('access_token', accessToken);
    
    // 🚨 Same result: victim's session linked to attacker's account
}
```

**Why implicit flow has CSRF vulnerability:**
- Tokens delivered in **URL fragment** (can be manipulated)
- Same session binding problem as authorization code
- **Plus** token exposure in browser history, referrer headers, etc.

---

### **3. Access Token (API Usage) - Different Type of CSRF**

**🎯 Target:** API actions, not account linking  
**⚔️ Weapon:** Victim's existing access token  
**💥 Impact:** Unauthorized actions (not account takeover)

```javascript
// API CSRF - different from login CSRF
// Attacker tricks victim into making API calls with victim's own tokens

// Victim has legitimate access token stored
const victimToken = localStorage.getItem('access_token');

// Attacker's malicious page triggers API calls
fetch('https://api.yourapp.com/delete-account', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${victimToken}`, // Victim's legitimate token
        'Content-Type': 'application/json'
    }
    // 🚨 If no CSRF protection, this succeeds
});
```

**Key differences from authorization code CSRF:**
- Uses **victim's own token** (not attacker's)
- Targets **specific actions** (not account linking)
- Prevented by **standard CSRF protection** (CSRF tokens, SameSite cookies)
- **Not** the same vulnerability as authorization code CSRF

---

## 🔑 **Why Authorization Code CSRF is Special**

### **The Critical Difference:**

| Flow Type | What Gets Mixed | Result |
|-----------|----------------|---------|
| **Authorization Code CSRF** | Attacker's code + Victim's session | Account linking attack |
| **API CSRF** | Victim's token + Attacker's request | Unauthorized action |

### **Authorization Code Flow Vulnerability:**
```
Attacker's Identity (via code) + Victim's Session = Account Takeover
```

### **API Usage Vulnerability:**
```
Victim's Identity (via token) + Attacker's Action = Unauthorized Operation
```

## 🛡️ **Protection Strategies**

### **For Authorization Code CSRF:**
```javascript
// State parameter (required)
const state = crypto.randomUUID();
sessionStore.set(state, { userId: currentUser.id, timestamp: Date.now() });

const oauthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${clientId}&` +
    `redirect_uri=${redirectUri}&` +
    `state=${state}&` + // Binds code to session
    `response_type=code`;
```

### **For API CSRF:**
```javascript
// Standard CSRF protection
app.use(csrf()); // CSRF middleware

// Or use SameSite cookies
app.use(session({
    cookie: { sameSite: 'strict' }
}));

// Or check Origin/Referer headers
app.use((req, res, next) => {
    if (req.headers.origin !== 'https://yourapp.com') {
        return res.status(403).send('CSRF detected');
    }
    next();
});
```

## 💡 **Key Takeaways**

### **Access Tokens vs Authorization Codes:**

1. **Authorization Code CSRF** = Identity confusion during login
2. **Access Token API CSRF** = Action confusion during API calls
3. **Both are dangerous**, but different attack vectors
4. **Different protections needed** for each

### **The Bottom Line:**
- **Authorization codes** need **state parameter** for session binding
- **Access tokens** need **standard CSRF protection** for API calls
- **Implicit flow** combines both vulnerabilities (deprecated)
- **Authorization Code + PKCE** is the secure modern approach

The original question about authorization codes having this CSRF issue is spot-on - it's a **specific vulnerability** in the OAuth2 authorization flow that requires **specific protection** (state parameter + PKCE)! 