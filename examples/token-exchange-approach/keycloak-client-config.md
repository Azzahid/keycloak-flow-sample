# Keycloak Client Configuration for External Google OAuth

## Overview
This configuration allows your external application to handle Google OAuth and then exchange tokens with Keycloak.

## Step 1: Create Keycloak Client

1. **Access Keycloak Admin Console**: http://localhost:8080/admin
2. **Login**: admin / admin_password
3. **Go to Clients** → **Create client**

### Client Configuration:
```
Client ID: your-app-client
Client type: OpenID Connect
Client authentication: ON (for confidential client)
```

### Settings Tab:
```
Valid redirect URIs: 
- http://localhost:3000/*
- https://your-domain.com/*

Valid post logout redirect URIs:
- http://localhost:3000/
- https://your-domain.com/

Web origins:
- http://localhost:3000
- https://your-domain.com

Root URL: http://localhost:3000
Admin URL: http://localhost:3000
```

### Advanced Settings:
```
Access Token Lifespan: 5 minutes (300 seconds)
Client Session Idle: 30 minutes
Client Session Max: 12 hours
```

## Step 2: Enable Required Grant Types

### In Client → Settings → Capability config:
- ✅ Client authentication
- ✅ Authorization
- ✅ Standard flow
- ✅ Direct access grants (for password flow)
- ✅ Token Exchange (if available)

### In Client → Advanced → Fine Grain OpenID Connect Configuration:
```
Access Token Signature Algorithm: RS256
ID Token Signature Algorithm: RS256
```

## Step 3: Client Credentials

### In Client → Credentials tab:
- Copy the **Client Secret** for your backend configuration

## Step 4: Configure Token Exchange (Optional)

If your Keycloak version supports token exchange:

1. **Go to Realm Settings** → **Tokens**
2. **Enable Token Exchange**: ON

### Add Token Exchange Policy:
1. **Go to Authorization** → **Policies** → **Create Policy**
2. **Type**: Token Exchange
3. **Name**: Google Token Exchange Policy
4. **Allow Token Exchange**: ON

## Step 5: User Federation (Optional)

To automatically create users from Google:

1. **Go to User Federation** → **Add provider** → **Custom**
2. **Create Custom User Federation** for Google users

## Step 6: Realm Roles

Create roles for your application:
1. **Go to Realm roles** → **Create role**
2. **Role name**: `app-user`
3. **Description**: Default role for application users

## Step 7: Default Roles

1. **Go to Realm settings** → **User registration**
2. **Default roles**: Add `app-user`

## Environment Variables for Backend

Update your `.env` file:
```bash
# Keycloak Client Configuration
KEYCLOAK_CLIENT_ID=your-app-client
KEYCLOAK_CLIENT_SECRET=your_client_secret_from_keycloak

# Google OAuth Configuration  
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Application URLs
APP_URL=http://localhost:3000
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=master
```

## Testing the Configuration

### 1. Test Token Exchange Endpoint
```bash
curl -X POST http://localhost:3000/api/auth/google-to-keycloak \
  -H "Content-Type: application/json" \
  -d '{
    "googleToken": "your_google_access_token",
    "profile": {
      "id": "google_user_id",
      "email": "user@example.com", 
      "name": "User Name",
      "imageUrl": "https://profile-image-url"
    }
  }'
```

### 2. Test Protected Endpoint
```bash
curl -X GET http://localhost:3000/api/protected \
  -H "Authorization: Bearer your_keycloak_access_token"
```

## Troubleshooting

### Common Issues:

1. **Token Exchange Not Working**
   - Ensure Token Exchange is enabled in realm settings
   - Check if client has proper permissions
   - Verify token exchange grant type is enabled

2. **User Creation Fails**
   - Check admin token permissions
   - Verify user creation endpoint accessibility
   - Ensure email uniqueness

3. **CORS Issues**
   - Add proper web origins in client settings
   - Configure CORS in your backend

4. **Invalid Client Configuration**
   - Verify client secret
   - Check redirect URIs match exactly
   - Ensure client authentication is properly configured 