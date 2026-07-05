# Stage A Stabilization Pull Requests

This document tracks all the pull requests created for Stage A of the codebase stabilization plan, outlining their branches, bases, and short descriptions of the changes.

## PR Summary & Recommended Merge Order

Please review and merge these PRs in the order listed below to avoid any merge conflicts (each branch was chained from the preceding one).

| # | Pull Request | Branch | Git Parent Branch | PR Base Branch | Description |
|---|---|---|---|---|---|
| 1 | **[PR #284](https://github.com/AndreiBozantan/svelte-axum-template/pull/284)** | `stage-a-user-status-enforcement` | `main` | `main` | Enforces checks on user status (`Active`) during authentication and token refreshes. Rejects suspended users. |
| 2 | **[PR #285](https://github.com/AndreiBozantan/svelte-axum-template/pull/285)** | `stage-a-trusted-proxy-config` | `stage-a-user-status-enforcement` | `main` | Introduces configurable trusted proxy verification (`trusted_proxy = true/false`) for secure rate limiting IP extraction. |
| 3 | **[PR #286](https://github.com/AndreiBozantan/svelte-axum-template/pull/286)** | `stage-a-security-headers` | `stage-a-trusted-proxy-config` | `main` | Adds standard security headers (nosniff, frame-ancestors, CSP, HSTS, Referrer-Policy) middleware layer globally. |
| 4 | **[PR #287](https://github.com/AndreiBozantan/svelte-axum-template/pull/287)** | `stage-a-request-body-limits` | `stage-a-security-headers` | `main` | Enforces global `2MB` request size limit and password (72 chars) / email (254 chars) max-length validations. |
| 5 | **[PR #288](https://github.com/AndreiBozantan/svelte-axum-template/pull/288)** | `stage-a-timeouts` | `stage-a-request-body-limits` | `main` | Sets a global `30s` request timeout layer and an explicit `10s` timeout on Google OAuth token exchange reqwest calls. |
| 6 | **[PR #289](https://github.com/AndreiBozantan/svelte-axum-template/pull/289)** | `stage-a-graceful-shutdown` | `stage-a-timeouts` | `main` | Listens for Unix `SIGTERM` in addition to `Ctrl+C` for zero-downtime container rollout graceful shutdowns. |
| 7 | **[PR #290](https://github.com/AndreiBozantan/svelte-axum-template/pull/290)** | `stage-a-docs-operations` | `stage-a-graceful-shutdown` | `main` | Creates `docs/design/operations.md` detailing the TLS proxy configuration and container graceful shutdown. |
| 8 | **[PR #291](https://github.com/AndreiBozantan/svelte-axum-template/pull/291)** | `stage-a-oauth-prompt` | `stage-a-docs-operations` | `main` | Appends `prompt=select_account` to the Google OAuth authorization URL to allow clean user account switching. |
| 9 | **[PR #292](https://github.com/AndreiBozantan/svelte-axum-template/pull/292)** | `stage-a-docs-plan-update` | `stage-a-oauth-prompt` | `main` | Updates the main `stabilization-plan.md` checklist with PR links and recommended merge order. |
