Replacing In-Memory Session Store with JWT Cookies
Currently, the OAuth flow uses an in-memory 
oauth_session_store
 (Arc<RwLock<HashMap<String, OAuthSessionEntry>>>) to manage the CSRF token (state) and 
redirect_url
 during the 
google_auth_init
 and 
google_auth_callback
 steps.

This works, but has a few drawbacks:

It's stateful, which means it won't scale automatically across multiple backend nodes.
If the backend restarts, all pending login sessions are dropped.
It requires periodic background cleanup to prevent memory bloat, which currently isn't fully implemented.
Proposed Changes
We can make the OAuth flow completely stateless by issuing a temporary, cryptographically signed cookie to the client during 
google_auth_init
.

[MODIFY] 
sso::get_google_auth_url
Remove 
store_session_entry
Serialize the 
redirect_url
 into a new JWT payload
Return the generated JWT to be set as a cookie instead of storing it into ArcContext
[MODIFY] 
sso::get_google_user_info
Remove the validation against the OAuthSessionStore
Decode the JWT cookie. If the signature is valid, verify the state parameter matches the JWT.
[MODIFY] 
auth::google_auth_init
Take the JWT returned by 
get_google_auth_url
 and append it as a Set-Cookie: oauth_state=...; HttpOnly; Secure; Max-Age=300; Path=/ header before redirecting to Google.
[MODIFY] 
auth::google_auth_callback
Extract the oauth_state cookie from the request.
Pass it to 
get_google_user_info
.
Clear the oauth_state cookie by returning a Max-Age=0 header along with the standard login cookies.
[MODIFY] Cleanup
Remove 
OAuthSessionEntry
, OAuthSessionStore, and 
create_oauth_session_store
 entirely from the codebase, including from core::Context.
User Review Required
IMPORTANT

Because we are switching the state mapping to be cookie-based, the OAuth callback must happen on the same exact domain that initiated it so the browser sends the cookie back. As long as your frontend and backend share the root domain (or localhost during dev), this is standard and secure.

Verification Plan
Start the server via cargo run in the backend.
Initiate a login flow.
Verify that oauth_state is set in the headers.
Verify that completing the flow redirects as expected and yields valid 
access_token
 and 
refresh_token
 cookies.


State parameter verification — the plan mentions verifying the state parameter matches the JWT. Make sure the state value is embedded inside the JWT payload when it's created in get_google_auth_url, not just compared loosely. The flow should be:

Generate random state
Embed it in JWT payload
Send state to Google as the OAuth state param
On callback, Google returns state → verify it matches what's in the JWT


One Gap in the Plan
The plan doesn't mention what happens if the oauth_state cookie is missing or expired in google_auth_callback — you'll want to return a clear error (e.g. AuthError::TokenInvalid or similar) rather than letting it panic or produce a confusing response.
