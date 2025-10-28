# High Priority
1. (auth.rs) Tokens are passed in the URL query parameters.
This is the most critical security issue. In the google_auth_callback function, after a successful login, the access_token and refresh_token are appended as query parameters to the redirect URL.

```rs
// in /Users/b/Code/svelaxum/backend/src/routes/auth.rs

let redirect_url_with_tokens = format!(
    "{}?oauth_success=true&access_token={}&refresh_token={}",
    final_redirect_url,
    jwt_token_response.access_token,
    jwt_token_response.refresh_token
);

Ok(axum::response::Redirect::to(&redirect_url_with_tokens))
```

Risk: Tokens in the URL can be exposed in several ways:

They are stored in the user's browser history.
They can be logged by the web server.
If the user clicks any link on the resulting page, the full URL with the tokens can be sent in the Referer header to the next site.
Recommendation: Do not pass tokens in the URL. A more secure pattern is to have the frontend and backend exchange the tokens via a POST request.

In the callback, generate a secure, one-time-use authorization code. Redirect the user back to the frontend with this code in the query string (e.g., https://your-frontend.com/login/callback?code=...).
The frontend receives this code and immediately makes a POST request to a new backend endpoint (e.g., /api/auth/token/exchange) with the code.
The backend verifies the one-time code and returns the JWT tokens in the JSON body of the response.


# Medium Priority
1. (sso.rs) In-Memory Storage for OAuth Sessions
As we discussed previously, the OAuthSessionStore is an in-memory HashMap. This will cause authentication to fail intermittently if you scale to more than one server.

Risk: This is primarily an availability and reliability issue, but it can also have security implications if it leads to unpredictable application behavior or flawed retry logic.

Recommendation: As the code comment suggests, replace the in-memory store with a distributed one like Redis or a database table.

2. (audit.rs) Potentially Unsafe IP Address Extraction
The extract_client_ip function trusts the x-forwarded-for header and takes the first IP address from the list.

Risk: The x-forwarded-for header can be easily spoofed by a malicious client. This means your audit logs could contain incorrect IP addresses, hindering a forensic investigation or allowing an attacker to masquerade as a different user.

Recommendation: The most reliable source for the client IP is the one from your trusted reverse proxy (e.g., your load balancer). Configure your proxy to set a specific, trusted header (like X-Real-IP) and have your application only read from that header. Your proxy should be configured to strip any incoming headers of the same name from the client.

# Low Priority / Defense-in-Depth
(auth.rs) Hardcoded HTTP Redirect: The fallback redirect URL in google_auth_callback is hardcoded to http://localhost:5173/login. Using HTTP, even for localhost, is not ideal. It would be better to make this configurable and use HTTPS.
(audit.rs) Logging of Sensitive Information: The log_oauth_redirecting function logs the state parameter (the CSRF token) in cleartext. While this token is short-lived, it's better to avoid logging secrets. Consider logging a hash of the state parameter instead.
(sso.rs) Open Redirect Risk with Subdomains: The validate_redirect_url function allows redirects to any subdomain of an allowed domain (e.g., *.example.com). If a subdomain could be compromised, it could be used to stage phishing attacks. For higher security, it's better to use an explicit allow-list of exact domain names.
