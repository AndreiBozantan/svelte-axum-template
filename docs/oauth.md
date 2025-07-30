# OAuth 2.0 Security Implementation Guide

This document explains the OAuth 2.0 flow and the security measures implemented in our SSO system.

## 🔄 OAuth 2.0 Flow Overview

OAuth is a protocol that allows users to login with third-party providers (like Google) without sharing their passwords with your application.

### Basic OAuth Flow:
1. **User clicks "Login with Google"** → Your app redirects to Google
2. **User authenticates with Google** → Google shows consent screen
3. **Google redirects back to your app** → With authorization code
4. **Your app exchanges code for tokens** → Gets user info from Google
5. **Your app creates session** → User is logged in

## 🛡️ CSRF (Cross-Site Request Forgery) Protection

### What is CSRF?
CSRF is an attack where a malicious website tricks a user's browser into making unwanted requests to your application.

### The Problem:
```
1. User visits malicious-site.com
2. Malicious site contains: <img src="https://yourapp.com/auth/oauth/google/callback?code=fake">
3. Browser automatically makes request to your app
4. Attacker could potentially hijack the OAuth flow
```

### Our Solution:
```rust
// 1. Generate random state token when starting OAuth
let (auth_url, csrf_token) = client
    .authorize_url(oauth2::CsrfToken::new_random)  // <- Random state
    .url();

// 2. Store the token in our session store
let session = OAuthSession {
    csrf_token: state.clone(),
    redirect_url,
    created_at: Utc::now(),
};
store.insert(state.clone(), session);

// 3. Validate token when Google redirects back
let session = store.remove(state).ok_or(Error::CsrfValidationFailed)?;
if session.csrf_token != state {
    return Err(Error::CsrfValidationFailed);
}
```

### How it works:
- **State Parameter**: OAuth includes a random `state` parameter in all requests
- **Session Storage**: We store the expected state value
- **Validation**: When Google redirects back, we verify the state matches
- **Attackers can't guess**: Random tokens prevent replay attacks

## 🔗 Redirect URL Security (Open Redirect Prevention)

### The Problem:
Without validation, attackers could redirect users to malicious sites:
```
https://yourapp.com/auth/oauth/google?redirect_url=https://evil-site.com
```

### Our Solution:
```rust
fn validate_redirect_url(url: &str, config: &cfg::OAuthSettings) -> Result<(), Error> {
    let parsed_url: Url = url.parse().map_err(|_| Error::InvalidRedirectUrl)?;
    
    // Check against allowed domains from configuration
    match parsed_url.host_str() {
        Some(host) => {
            let is_allowed = config.allowed_redirect_domains.iter()
                .any(|allowed| host == allowed || host.ends_with(&format!(".{}", allowed)));
            
            if !is_allowed {
                tracing::warn!("Rejected redirect to unauthorized host: {}", host);
                return Err(Error::InvalidRedirectUrl);
            }
        }
        None => return Err(Error::InvalidRedirectUrl),
    }
    
    // Ensure HTTPS in production
    if parsed_url.scheme() != "https" && !parsed_url.host_str().unwrap_or("").contains("localhost") {
        return Err(Error::InvalidRedirectUrl);
    }
    
    Ok(())
}
```

### Configuration:
```rust
// In oauth_settings.rs
pub struct OAuthSettings {
    pub allowed_redirect_domains: Vec<String>,  // Whitelist of safe domains
}

// In configs.production.toml
allowed_redirect_domains = ["yourdomain.com", "www.yourdomain.com"]
```

### How it protects:
- **Domain Whitelist**: Only allows redirects to pre-approved domains
- **HTTPS Enforcement**: Prevents redirect to insecure HTTP in production
- **Subdomain Support**: Allows `app.yourdomain.com` if `yourdomain.com` is allowed

## 🕒 OAuth Session Handling

### The Challenge:
OAuth flows can take time (user needs to authenticate with Google), so we need to:
- Remember what the user was trying to do
- Prevent session hijacking
- Clean up expired sessions

### Our Session Store:
```rust
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub csrf_token: String,           // For CSRF protection
    pub redirect_url: Option<String>, // Where to send user after login
    pub created_at: DateTime<Utc>,    // For timeout handling
}

// In-memory store (use Redis in production)
pub type OAuthSessionStore = Arc<RwLock<HashMap<String, OAuthSession>>>;
```

### Session Lifecycle:

#### 1. **Session Creation** (when user clicks "Login with Google"):
```rust
pub async fn get_google_auth_url(
    config: &cfg::OAuthSettings,
    session_store: &OAuthSessionStore,
    redirect_url: Option<String>,
) -> Result<(Url, String), Error> {
    // Generate OAuth URL with random state
    let (auth_url, csrf_token) = client.authorize_url(oauth2::CsrfToken::new_random).url();
    
    // Create session
    let session = OAuthSession {
        csrf_token: state.clone(),
        redirect_url,
        created_at: Utc::now(),
    };
    
    // Store session with cleanup
    {
        let mut store = session_store.write().await;
        
        // Clean up expired sessions
        let timeout_minutes = Duration::minutes(config.session_timeout_minutes as i64);
        let cutoff = Utc::now() - timeout_minutes;
        store.retain(|_, session| session.created_at > cutoff);
        
        // Store new session
        store.insert(state.clone(), session);
    }
    
    Ok((auth_url, state))
}
```

#### 2. **Session Validation** (when Google redirects back):
```rust
pub async fn get_google_user_info(
    context: &core::ArcContext, 
    code: &str,
    state: &str,
    session_store: &OAuthSessionStore,
) -> Result<(GoogleUserInfo, Option<String>), Error> {
    // Retrieve and remove session (one-time use)
    let session = {
        let mut store = session_store.write().await;
        store.remove(state).ok_or(Error::CsrfValidationFailed)?
    };
    
    // Validate CSRF token
    if session.csrf_token != state {
        return Err(Error::CsrfValidationFailed);
    }
    
    // Check session hasn't expired
    let timeout_minutes = Duration::minutes(context.settings.oauth.session_timeout_minutes as i64);
    let session_age = Utc::now() - session.created_at;
    if session_age > timeout_minutes {
        return Err(Error::SessionNotFound);
    }
    
    // Session is valid, continue with OAuth flow...
}
```

### Key Security Features:

#### **One-Time Use**: 
Sessions are removed after use to prevent replay attacks

#### **Timeout Protection**: 
Sessions expire after configurable time (5-10 minutes)

#### **Automatic Cleanup**: 
Expired sessions are automatically removed to prevent memory leaks

#### **Thread Safety**: 
Uses `Arc<RwLock<>>` for safe concurrent access

## 🔍 Complete Flow Example

Here's what happens when a user logs in:

```
1. User clicks "Login with Google"
   ↓
2. Your app generates: state="abc123", stores session
   ↓
3. Redirect to: https://accounts.google.com/oauth/authorize?state=abc123&client_id=...
   ↓
4. User authenticates with Google
   ↓
5. Google redirects to: https://yourapp.com/auth/oauth/google/callback?code=xyz789&state=abc123
   ↓
6. Your app validates: state matches stored session ✓
   ↓
7. Exchange code for access token with Google
   ↓
8. Get user info from Google API
   ↓
9. Create user session in your app
   ↓
10. Redirect user to app with JWT tokens
```

## 🛡️ Why These Security Measures Matter

1. **CSRF Protection**: Prevents attackers from hijacking OAuth flows
2. **Redirect URL Validation**: Stops open redirect attacks that could steal tokens
3. **Session Management**: Ensures OAuth state can't be replayed or hijacked
4. **Timeouts**: Limits window for attacks
5. **Cleanup**: Prevents resource exhaustion

## 🚨 Common Attack Scenarios Prevented

### 1. CSRF Attack Prevention
**Attack**: Malicious site tries to initiate OAuth flow on behalf of user
```html
<!-- Malicious site -->
<iframe src="https://yourapp.com/auth/oauth/google/callback?code=stolen&state=guessed"></iframe>
```
**Prevention**: Our random state tokens can't be guessed by attackers

### 2. Open Redirect Prevention
**Attack**: Attacker redirects user to malicious site after login
```
https://yourapp.com/auth/oauth/google?redirect_url=https://phishing-site.com
```
**Prevention**: Domain whitelist blocks unauthorized redirects

### 3. Session Replay Prevention
**Attack**: Attacker intercepts and reuses OAuth session
**Prevention**: One-time use sessions are immediately deleted after use

### 4. Session Hijacking Prevention
**Attack**: Attacker tries to use old/expired OAuth sessions
**Prevention**: Configurable timeouts invalidate old sessions

## 🔧 Configuration Examples

### Development Environment
```toml
[oauth]
google_client_id = ""  # Set via environment
google_client_secret = ""  # Set via environment
google_redirect_uri = "http://localhost:3000/auth/oauth/google/callback"
allowed_redirect_domains = ["localhost", "127.0.0.1"]
session_timeout_minutes = 10
```

### Production Environment
```toml
[oauth]
google_client_id = ""  # Set via environment
google_client_secret = ""  # Set via environment
google_redirect_uri = "https://yourdomain.com/auth/oauth/google/callback"
allowed_redirect_domains = ["yourdomain.com", "www.yourdomain.com", "app.yourdomain.com"]
session_timeout_minutes = 5  # Shorter timeout for production
```

## 🔒 Security Best Practices Implemented

1. **Environment Variables**: OAuth secrets never stored in code
2. **HTTPS Enforcement**: Production redirects must use HTTPS
3. **Domain Validation**: Strict whitelist of allowed redirect domains
4. **Session Timeouts**: Configurable timeouts prevent long-lived sessions
5. **Automatic Cleanup**: Memory management prevents DoS attacks
6. **Comprehensive Logging**: All security events are logged for monitoring
7. **Rate Limiting**: Prevents OAuth endpoint abuse
8. **Input Validation**: All user inputs are validated and sanitized

This creates a secure OAuth implementation that's resistant to common attacks while maintaining a smooth user experience!
