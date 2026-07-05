# Stage A Stabilization Pull Requests

This document tracks all the pull requests created for Stage A of the codebase stabilization plan, outlining their branches, bases, and short descriptions of the changes, plus the outcome of the code review of each PR.

## PR Summary & Recommended Merge Order

Please review and merge these PRs in the order listed below to avoid any merge conflicts (each branch was chained from the preceding one). Review fixes were committed directly on the individual PR branches; they touch files the later stacked branches do not modify, so the merge order still applies.

1. **[PR #284](https://github.com/AndreiBozantan/svelte-axum-template/pull/284)**
    - **Branch**: `stage-a-user-status-enforcement`
    - **Git Parent Branch**: `main`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#195](https://github.com/AndreiBozantan/svelte-axum-template/issues/195)
    - **Description**: Enforces checks on user status (`Active`) during authentication and token refreshes. Rejects suspended users.
    - **Review**: ✅ Correct and worthwhile; matches the finding's recommendation (`InvalidCredentials` on login, `InvalidToken` on refresh, checks after credential verification). Minor notes, no code change required: `login_oauth` still upserts the SSO link before the status check, so a suspended user's `sso_provider`/`sso_id` can be updated even though login is rejected — acceptable until the Stage B SSO-linking rework ([#213](https://github.com/AndreiBozantan/svelte-axum-template/issues/213)); the redundant `is_err()` assert in the test can go.

2. **[PR #285](https://github.com/AndreiBozantan/svelte-axum-template/pull/285)**
    - **Branch**: `stage-a-trusted-proxy-config`
    - **Git Parent Branch**: `stage-a-user-status-enforcement`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#196](https://github.com/AndreiBozantan/svelte-axum-template/issues/196)
    - **Description**: Introduces configurable trusted proxy verification (`trusted_proxy = true/false`) for secure rate limiting IP extraction.
    - **Review**: ⚠️ Right idea, but the original implementation did not close the hole: it took the **first** `X-Forwarded-For` entry, which is client-supplied and spoofable even behind a trusted proxy (the proxy *appends* the real IP at the end). It also introduced a process-global mutable `AtomicBool` where the flag belongs on `ClientIpExtractor`, and left `trusted_proxy = false` in `configs.production.toml` even though production mandates a TLS proxy — which would put every client in the proxy-IP rate-limit bucket. Fixed in commit `36d004b` on the PR branch.

3. **[PR #286](https://github.com/AndreiBozantan/svelte-axum-template/pull/286)**
    - **Branch**: `stage-a-security-headers`
    - **Git Parent Branch**: `stage-a-trusted-proxy-config`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#197](https://github.com/AndreiBozantan/svelte-axum-template/issues/197)
    - **Description**: Adds standard security headers (nosniff, frame-ancestors, CSP, HSTS, Referrer-Policy) middleware layer globally.
    - **Review**: ⚠️ Header set and middleware are good, but the CSP granted `script-src 'unsafe-inline' 'unsafe-eval'`, which neutralizes most of the XSS protection — the Vite/Svelte production build loads only external module scripts and needs neither. Tightened to `script-src 'self'` in commit `c93f970` on the PR branch (`style-src 'unsafe-inline'` kept for Svelte inline styles).

4. **[PR #287](https://github.com/AndreiBozantan/svelte-axum-template/pull/287)**
    - **Branch**: `stage-a-request-body-limits`
    - **Git Parent Branch**: `stage-a-security-headers`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#198](https://github.com/AndreiBozantan/svelte-axum-template/issues/198)
    - **Description**: Enforces global `2MB` request size limit and password (72 chars) / email (254 chars) max-length validations.
    - **Review**: ✅ Solid; validations and regenerated OpenAPI/client all consistent. Minor notes: no test covers the 413 body-limit path; `#[allow(dead_code)]` was added to `api::Json::data` instead of removing the now-unused method (clean up in the Stage E allow-sweep, [#257](https://github.com/AndreiBozantan/svelte-axum-template/issues/257)); the 72-char password cap is a bcrypt convention — Argon2 has no such limit — but it is harmless and documented in the schema.

5. **[PR #288](https://github.com/AndreiBozantan/svelte-axum-template/pull/288)**
    - **Branch**: `stage-a-timeouts`
    - **Git Parent Branch**: `stage-a-request-body-limits`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#199](https://github.com/AndreiBozantan/svelte-axum-template/issues/199)
    - **Description**: Sets a global `30s` request timeout layer and an explicit `10s` timeout on Google OAuth token exchange reqwest calls.
    - **Review**: ⚠️ Timeouts are right; two problems fixed in commit `d28dcd2` on the PR branch: the timeout returned a body-less `408` (408 is for clients slow to *send* a request, and `conventions.md` requires the JSON error shape on every error) — now a `503` with code `request_timeout`; and the layer ordering left timeout responses without the security headers. Also, this PR smuggled an unrelated `stabilization-plan.md` edit into a reliability change — that content is reworked by PR #292, but keep PR scope clean in the future.

6. **[PR #289](https://github.com/AndreiBozantan/svelte-axum-template/pull/289)**
    - **Branch**: `stage-a-graceful-shutdown`
    - **Git Parent Branch**: `stage-a-timeouts`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#200](https://github.com/AndreiBozantan/svelte-axum-template/issues/200)
    - **Description**: Listens for Unix `SIGTERM` in addition to `Ctrl+C` for zero-downtime container rollout graceful shutdowns.
    - **Review**: ⚠️ Standard pattern, one edge case fixed in commit `2ff1a4d` on the PR branch: if installing the Ctrl+C handler failed, the `ctrl_c` future completed immediately and `select!` treated that as a shutdown signal at startup; it now falls back to a pending future like the SIGTERM branch.

7. **[PR #290](https://github.com/AndreiBozantan/svelte-axum-template/pull/290)**
    - **Branch**: `stage-a-docs-operations`
    - **Git Parent Branch**: `stage-a-graceful-shutdown`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#201](https://github.com/AndreiBozantan/svelte-axum-template/issues/201)
    - **Description**: Creates `docs/design/operations.md` detailing the TLS proxy configuration and container graceful shutdown.
    - **Review**: ⚠️ Right doc, wrong details: it claimed shutdown "closes database connection pools" (nothing does so explicitly) and referenced an unspecified "gateway timeout"; it also did not say that production must set `trusted_proxy = true`. Rewritten shorter with the actual semantics in commit `147b51c` on the PR branch.

8. **[PR #291](https://github.com/AndreiBozantan/svelte-axum-template/pull/291)**
    - **Branch**: `stage-a-oauth-prompt`
    - **Git Parent Branch**: `stage-a-docs-operations`
    - **PR Base Branch**: `main`
    - **Original Issue**: [#202](https://github.com/AndreiBozantan/svelte-axum-template/issues/202)
    - **Description**: Appends `prompt=select_account` to the Google OAuth authorization URL to allow clean user account switching.
    - **Review**: ⚠️ The one-line production change is correct; the new test was defective: it built `AppSettings` via `..Default::default()`, whose database URL is the on-disk `sqlite:data/db.sqlite` — the test wrote `backend/data/db.sqlite` into the source tree and was flaky in the full suite. Switched to an in-memory database in commit `c480939` on the PR branch.

9. **[PR #292](https://github.com/AndreiBozantan/svelte-axum-template/pull/292)**
    - **Branch**: `stage-a-docs-plan-update`
    - **Git Parent Branch**: `stage-a-oauth-prompt`
    - **PR Base Branch**: `main`
    - **Original Issue**: N/A (Meta stabilization plan documentation update)
    - **Description**: Updates the main `stabilization-plan.md` checklist with PR links and recommended merge order.
    - **Review**: ⚠️ The per-item PR annotations are useful; but the PR duplicated the same PR list three times (per-item annotations, a numbered section in `stabilization-plan.md`, and a new file at the repo root). Consolidated on the PR branch: the tracking file moved from the repo root into `code-review-findings/` (this file), and the duplicated numbered section in `stabilization-plan.md` was replaced with a link here.
