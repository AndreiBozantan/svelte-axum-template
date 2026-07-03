# 05 — HTTP & Transport Security

Rate limiting exists and cookies are well-configured, but **security response headers are
entirely missing** and TLS/HSTS is assumed to be handled by an unspecified proxy.

---

## 5.1 — No security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy)
- **GitHub Issue:** [#197](https://github.com/AndreiBozantan/svelte-axum-template/issues/197)

- **Severity:** Important
- **Location:** `backend/router.rs:56-73` — layers applied are trace + catch-panic +
  rate-limiting only. No `SetResponseHeader` / security-header layer. Asset responses in
  `backend/platform/shared/assets.rs` set only content-type/cache/etag.
- **Finding:** The app serves an HTML SPA and a cookie-auth API but sends none of the standard
  security headers. No `Content-Security-Policy`, so any injected script/HTML would run
  unrestricted; no `X-Content-Type-Options: nosniff`; no `X-Frame-Options`/`frame-ancestors`
  (clickjacking); no `Strict-Transport-Security`; no `Referrer-Policy`; no `Permissions-Policy`.
- **Risk:** Weaker XSS containment and clickjacking/MIME-sniffing exposure for a
  cookie-authenticated app.
- **Recommendation:** Add a `tower_http::set_header` (or a small middleware) applying, at
  minimum: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`), a CSP tuned for the SPA
  (note the app loads Google Fonts in `AppSidebar.svelte` — factor that into `style-src`/
  `font-src`), and `Strict-Transport-Security` when serving over HTTPS. Consider
  `Permissions-Policy` to disable unused features.

---

## 5.2 — HTTPS enforcement / HTTP→HTTPS redirect is undocumented and unimplemented in-app
- **GitHub Issue:** [#201](https://github.com/AndreiBozantan/svelte-axum-template/issues/201)

- **Severity:** Important
- **Location:** `backend/server.rs:92-104` binds plain TCP; `data/configs.production.toml`
  binds `0.0.0.0:3000`; cookies are `Secure`-only.
- **Finding:** The server terminates plain HTTP. Cookies are marked `Secure` and use
  `__Host-`/`__Secure-` prefixes, which means **they will not be sent over plain HTTP at all**
  — so if the app is ever reached over HTTP (misconfigured proxy, direct exposure), auth
  silently breaks and there is no HTTP→HTTPS redirect. TLS is entirely delegated to an
  unspecified external component with no documentation of that requirement.
- **Risk:** Deploy-time footgun; no in-repo guarantee that transport is encrypted.
- **Recommendation:** Document the mandatory TLS-terminating proxy requirement prominently
  (README + conventions), and/or add an optional HTTP→HTTPS redirect and HSTS. Make the
  "must be behind HTTPS" assumption explicit alongside the `X-Forwarded-*` trust assumption
  (see 01.3).

---

## 5.3 — Global rate-limit key can be spoofed via forwarding headers
- **GitHub Issue:** [#196](https://github.com/AndreiBozantan/svelte-axum-template/issues/196)

- **Severity:** Important (cross-listed with 01.3)
- **Location:** `backend/platform/shared/rate_limiter.rs:83-105`.
- **Finding:** `extract_client_ip` trusts `X-Forwarded-For`/`X-Real-IP` unconditionally, so
  both the global and login limiters can be evaded by rotating a spoofed header value when the
  app is not behind a header-sanitizing proxy.
- **Risk:** Rate limiting becomes ineffective in direct-exposure deployments.
- **Recommendation:** Gate header trust behind an explicit `trusted_proxy` setting; otherwise
  key on the socket peer IP. See 01.3.

---

## 5.4 — CORS intentionally disabled; correct for current architecture

- **Severity:** Informational
- **Location:** `docs/api/conventions.md:201-207`; no CORS layer in `router.rs`.
- **Finding:** Same-origin SPA (embedded assets in prod, Vite proxy in dev) means no CORS is
  needed, and none is enabled — which is the safe default. Documented well. No change needed
  until/unless the frontend is split to another origin.

---

## 5.5 — Cookie configuration is strong; verified

- **Severity:** Informational
- **Location:** `backend/platform/shared/cookies.rs:61-156`.
- **Finding:** Access token uses `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`,
  path `/`; refresh token uses `__Secure-` prefix, path `/api/auth/`, `SameSite=Strict`. The
  non-sensitive `logged_in` JS-readable cookie is `SameSite=Lax` and holds only a boolean.
  This is a correct, defense-in-depth setup. Note: with `SameSite=Strict`, top-level
  navigations from external links won't carry the auth cookie on first hit — acceptable for an
  SPA, but be aware if deep-link SSR is ever added.
