# 01 — Authentication & Session Management

Overall this is the strongest part of the codebase. Findings below are refinements,
plus a couple of real correctness gaps.

---

## 1.1 — Suspended/archived users can still authenticate and refresh

- **Severity:** Important
- **Location:** `backend/platform/identity/auth/auth_service.rs:124-167` (`login`),
  `:224-276` (`refresh`); `users` table has a `status` column
  (`onboarding|active|suspended|archived`).
- **Finding:** `login` and `refresh` never check `user.status`. A user who is `suspended`
  or `archived` can still log in with a valid password, and existing refresh tokens keep
  minting new access tokens. The status field exists in the schema and domain model but is
  never enforced.
- **Risk:** Account suspension is a core security control (offboarding, abuse response,
  ban enforcement). Today it is cosmetic — suspending a user does nothing.
- **Recommendation:** After a successful credential/refresh check, reject non-`Active`
  statuses with `Error::InvalidCredentials` (login) / `Error::InvalidToken` (refresh).
  On suspend/archive, also revoke all refresh tokens (`revoke_all_for_user`). Add tests
  for "suspended user cannot log in" and "suspended user's refresh token is rejected."

---

## 1.2 — `logout` does not revoke the access token, only the refresh token

- **Severity:** Minor (inherent to stateless JWT, but worth documenting)
- **Location:** `backend/platform/identity/auth/auth_api.rs:144-160`,
  `backend/router.rs:85-93` (`auth_middleware`).
- **Finding:** Logout revokes the refresh token and clears cookies, but the already-issued
  access token remains valid until `exp` (default 16 min). There is no deny-list check in
  `auth_middleware`, so a copied access token keeps working after logout.
- **Risk:** For a shared/public device or a stolen access token, "log out" does not
  immediately end access. 16 minutes is a bounded but real window.
- **Recommendation:** Accept the trade-off explicitly and document it, or add a lightweight
  revoked-jti check for access tokens if the threat model needs immediate revocation. At
  minimum, note the window in the security docs. Keeping access-token lifetime short (it is)
  is the right mitigation.

---

## 1.3 — Login rate limiter is keyed only by client IP, not by account

- **Severity:** Important
- **Location:** `backend/platform/shared/rate_limiter.rs:83-105`
  (`extract_client_ip`), `backend/platform/identity/auth/auth_api.rs:29-33`.
- **Finding:** The login/register limiter and the account-lockout logic are both keyed
  per-IP / per-account respectively, but the limiter trusts `X-Forwarded-For` / `X-Real-IP`
  from *any* client. When the service is exposed directly (no trusted proxy), an attacker
  can set `X-Forwarded-For` to a random value per request and completely bypass the login
  rate limiter. The per-account exponential lockout (`auth_service.rs:334-352`) still
  applies, but that lockout can itself be weaponized (see 1.4).
- **Risk:** Credential-stuffing / brute force against the login endpoint if deployed
  without a proxy that strips client-supplied forwarding headers.
- **Recommendation:** Make the trusted-proxy assumption explicit and configurable. Only
  honor `X-Forwarded-For`/`X-Real-IP` when a `trusted_proxy` config flag is set; otherwise
  use the socket `ConnectInfo` peer address. Document that the app must sit behind a proxy
  that overwrites these headers.

---

## 1.4 — Account lockout enables trivial denial-of-service against a known account

- **Severity:** Minor
- **Location:** `backend/platform/identity/auth/auth_service.rs:334-352`
  (`lockout_duration_minutes` / `is_temporarily_locked`), `:150-156`.
- **Finding:** After 5 failed attempts the account is locked with exponential backoff
  (up to ~17h). Because the failed-login counter is keyed purely on the account and lockout
  is checked before password verification, anyone who knows a victim's email can lock them
  out indefinitely by submitting wrong passwords. There is no distinction between "attacker
  IP" and "legitimate user IP."
- **Risk:** Targeted account lockout DoS. Common trade-off, but should be a conscious one.
- **Recommendation:** Consider IP-scoped throttling in addition to account lockout, or a
  CAPTCHA/step-up rather than hard lockout, or cap lockout at a few minutes. At minimum
  document the behavior so operators know it exists.

---

## 1.5 — `refresh` issues a new token before validating the token hash matches

- **Severity:** Minor (correct today, but fragile ordering)
- **Location:** `backend/platform/identity/auth/auth_service.rs:224-276`.
- **Finding:** In `refresh`, the code `try_revoke_active_by_jti` (marks revoked) first, then
  compares `token_user_id`, then compares `constant_time_eq(stored_token.token_hash, hash)`.
  The JWT signature already guarantees integrity, so a forged JTI with the wrong hash is not
  a real risk — but the current ordering revokes the stored row *before* the hash check, so
  a malformed-but-signed reused token can flip a valid token to revoked. Given JWTs are
  signed this is largely theoretical, but the hash check is then redundant defense-in-depth
  that runs too late to protect the row.
- **Risk:** Low. Mostly a clarity/ordering concern.
- **Recommendation:** Either drop the now-redundant hash comparison (the signed JTI is the
  identifier and the signature is the integrity guarantee), or move the comparison before
  the state mutation. Document why the hash column exists (it predates signed JTIs?).

---

## 1.6 — Frontend token-refresh timing state is stored in `localStorage`

- **Severity:** Minor
- **Location:** `frontend/src/lib/auth-refresh-manager.ts:99-131,217-233`.
- **Finding:** Only *timing metadata* (`auth_expires_at`, `auth_lead_time_ms`) lives in
  `localStorage` — no token material, which is correct and matches the HttpOnly-cookie
  design. The cross-tab coordination via the `storage` event and Web Locks is well done.
  One rough edge: on logout, `clearRefreshTimer()` removes the keys, but a background tab
  that is mid-`proactiveRefresh` could re-populate them; and the `focus` handler reschedules
  a timer purely from `localStorage` even if the session was invalidated server-side.
- **Risk:** Minor — a stale timer fires a refresh that 401s and cleanly logs out. No security
  impact.
- **Recommendation:** Gate the `focus`/`storage` rescheduling on `AppState.isLoggedIn`, and
  clear timing keys in the auth-failure callback too. Low priority.

---

## 1.7 — OAuth state-cookie design is sound; verify one edge

- **Severity:** Minor (informational)
- **Location:** `backend/platform/identity/oauth/oauth_service.rs:96-128,244-317`.
- **Finding:** The signed-not-encrypted `oauth_state` JWT design is well reasoned and
  documented (PKCE verifier + CSRF hash, short exp, callback-scoped cookie). CSRF is checked
  with `constant_time_eq`. Good. One note: `begin_google_flow` falls back to `redirect_url = "/"`
  when validation fails silently, which is safe, but the callback re-validates the stored
  `redirect_url` (`:314`) — belt and suspenders, good. No change required; documenting that
  this area was reviewed and is acceptable.
