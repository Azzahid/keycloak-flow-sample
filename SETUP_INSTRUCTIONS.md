# Keycloak with Google OAuth Integration Setup

This guide will help you set up Keycloak with Google OAuth integration and a custom login theme.

## Prerequisites

- Docker and Docker Compose installed
- Google Cloud Console access
- Domain or localhost setup

## Step 1: Google OAuth Setup

### 1.1 Create Google OAuth Client

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Navigate to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth 2.0 Client IDs**
5. Configure the OAuth consent screen if not already done
6. For Application type, select **Web application**
7. Add authorized redirect URIs:
   - `http://localhost:8080/realms/master/broker/google/endpoint`
   - `https://your-domain.com/realms/master/broker/google/endpoint` (for production)

### 1.2 Update Environment Variables

1. Copy the Client ID and Client Secret from Google Console
2. Update the `.env` file with your Google credentials:

```bash
GOOGLE_CLIENT_ID=your_actual_google_client_id
GOOGLE_CLIENT_SECRET=your_actual_google_client_secret
```

## Step 2: Download Google Logo

1. Download the official Google logo from [Google's Branding Guidelines](https://developers.google.com/identity/branding-guidelines)
2. Save as `google-logo.png` in `themes/custom/login/resources/img/`
3. Ensure the image is approximately 20x20 pixels for best display

## Step 3: Start the Services

```bash
# Start Keycloak and PostgreSQL
docker-compose up -d

# Check if services are running
docker-compose ps
```

## Step 4: Access Keycloak Admin Console

1. Open browser and go to: http://localhost:8080
2. Click on **Administration Console**
3. Login with:
   - Username: `admin`
   - Password: `admin_password`

## Step 5: Configure Google Identity Provider

### 5.1 Manual Configuration (if realm import doesn't work)

1. In Keycloak Admin Console, go to **Identity Providers**
2. Click **Add provider** > **Google**
3. Configure the following:
   - **Alias**: `google`
   - **Display Name**: `Google`
   - **Client ID**: Your Google Client ID
   - **Client Secret**: Your Google Client Secret
   - **Scope**: `openid profile email`
   - **Trust Email**: `ON`
4. Click **Save**

### 5.2 Update Redirect URI

1. Copy the **Redirect URI** shown in Keycloak
2. Add this URI to your Google OAuth client in Google Cloud Console

## Step 6: Set Custom Theme

1. In Keycloak Admin Console, go to **Realm Settings**
2. Click on **Themes** tab
3. Set **Login Theme** to `custom`
4. Click **Save**

## Step 7: Test the Setup

### 7.1 Test Direct Login

1. Open a new incognito/private browser window
2. Go to: http://localhost:8080/realms/master/account
3. You should see the custom login page with Google login button
4. Test both direct login and Google login

### 7.2 Create Test Application

To test SSO integration, you can create a test client:

1. In Keycloak Admin Console, go to **Clients**
2. Click **Create client**
3. Set:
   - **Client ID**: `test-app`
   - **Client type**: `OpenID Connect`
   - **Client authentication**: `OFF` (for public client)
4. Configure **Valid redirect URIs**: `http://localhost:3000/*`
5. Save and test

## Step 8: Application Integration

### For Frontend Applications (React, Vue, Angular)

Use libraries like:
- `@keycloak-js/keycloak-js`
- `keycloak-angular`
- `@react-keycloak/web`

Example integration:
```javascript
import Keycloak from 'keycloak-js';

const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'master',
  clientId: 'your-client-id',
});

keycloak.init({ onLoad: 'login-required' });
```

### For Backend Applications

Use OIDC/OAuth2 libraries to validate tokens:
- Node.js: `keycloak-connect`
- Java: `keycloak-spring-boot-starter`
- Python: `python-keycloak`

## Step 9: Production Considerations

### Security

1. Change default admin password
2. Use HTTPS in production
3. Configure proper CORS settings
4. Set up proper database security
5. Use secrets management for credentials

### Performance

1. Configure database connection pooling
2. Set up Keycloak clustering for high availability
3. Use external database (not Docker)
4. Configure proper resource limits

### Monitoring

1. Enable Keycloak metrics
2. Set up logging
3. Monitor authentication flows
4. Set up alerts for failed login attempts

## Troubleshooting

### Common Issues

1. **Google login redirects to error page**
   - Check redirect URI in Google Console
   - Verify Client ID and Secret
   - Ensure realm name matches

2. **Custom theme not loading**
   - Check theme folder structure
   - Restart Keycloak after theme changes
   - Verify theme name in realm settings

3. **Database connection issues**
   - Check PostgreSQL is running
   - Verify database credentials
   - Check network connectivity

### Debug Steps

1. Check Keycloak logs: `docker-compose logs keycloak`
2. Check PostgreSQL logs: `docker-compose logs postgres`
3. Enable debug logging in Keycloak admin console
4. Test endpoints with curl/Postman

## File Structure

```
keycloak/
├── docker-compose.yml
├── .env
├── SETUP_INSTRUCTIONS.md
├── themes/
│   └── custom/
│       └── login/
│           ├── theme.properties
│           ├── login.ftl
│           └── resources/
│               ├── css/
│               │   └── custom.css
│               └── img/
│                   └── google-logo.png
└── realm-config/
    └── realm-export.json
```

## Next Steps

1. Customize the theme further
2. Add more identity providers (Facebook, GitHub, etc.)
3. Configure user federation
4. Set up proper user roles and permissions
5. Implement logout functionality
6. Add multi-factor authentication

For more advanced configurations, refer to the [Keycloak Documentation](https://www.keycloak.org/documentation). 