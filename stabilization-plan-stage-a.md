# Stage A Stabilization Pull Requests

This document tracks all the pull requests created for Stage A of the codebase stabilization plan, outlining their branches, bases, and short descriptions of the changes.

## PR Summary & Recommended Merge Order

Please review and merge these PRs in the order listed below to avoid any merge conflicts (each branch was chained from the preceding one).

1. **[PR #284](https://github.com/AndreiBozantan/svelte-axum-template/pull/284)**
   - **Branch**: `stage-a-user-status-enforcement`
   - **Git Parent Branch**: `main`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#195](https://github.com/AndreiBozantan/svelte-axum-template/issues/195)
   - **Description**: Enforces checks on user status (`Active`) during authentication and token refreshes. Rejects suspended users.

2. **[PR #285](https://github.com/AndreiBozantan/svelte-axum-template/pull/285)**
   - **Branch**: `stage-a-trusted-proxy-config`
   - **Git Parent Branch**: `stage-a-user-status-enforcement`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#196](https://github.com/AndreiBozantan/svelte-axum-template/issues/196)
   - **Description**: Introduces configurable trusted proxy verification (`trusted_proxy = true/false`) for secure rate limiting IP extraction.

3. **[PR #286](https://github.com/AndreiBozantan/svelte-axum-template/pull/286)**
   - **Branch**: `stage-a-security-headers`
   - **Git Parent Branch**: `stage-a-trusted-proxy-config`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#197](https://github.com/AndreiBozantan/svelte-axum-template/issues/197)
   - **Description**: Adds standard security headers (nosniff, frame-ancestors, CSP, HSTS, Referrer-Policy) middleware layer globally.

4. **[PR #287](https://github.com/AndreiBozantan/svelte-axum-template/pull/287)**
   - **Branch**: `stage-a-request-body-limits`
   - **Git Parent Branch**: `stage-a-security-headers`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#198](https://github.com/AndreiBozantan/svelte-axum-template/issues/198)
   - **Description**: Enforces global `2MB` request size limit and password (72 chars) / email (254 chars) max-length validations.

5. **[PR #288](https://github.com/AndreiBozantan/svelte-axum-template/pull/288)**
   - **Branch**: `stage-a-timeouts`
   - **Git Parent Branch**: `stage-a-request-body-limits`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#199](https://github.com/AndreiBozantan/svelte-axum-template/issues/199)
   - **Description**: Sets a global `30s` request timeout layer and an explicit `10s` timeout on Google OAuth token exchange reqwest calls.

6. **[PR #289](https://github.com/AndreiBozantan/svelte-axum-template/pull/289)**
   - **Branch**: `stage-a-graceful-shutdown`
   - **Git Parent Branch**: `stage-a-timeouts`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#200](https://github.com/AndreiBozantan/svelte-axum-template/issues/200)
   - **Description**: Listens for Unix `SIGTERM` in addition to `Ctrl+C` for zero-downtime container rollout graceful shutdowns.

7. **[PR #290](https://github.com/AndreiBozantan/svelte-axum-template/pull/290)**
   - **Branch**: `stage-a-docs-operations`
   - **Git Parent Branch**: `stage-a-graceful-shutdown`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#201](https://github.com/AndreiBozantan/svelte-axum-template/issues/201)
   - **Description**: Creates `docs/design/operations.md` detailing the TLS proxy configuration and container graceful shutdown.

8. **[PR #291](https://github.com/AndreiBozantan/svelte-axum-template/pull/291)**
   - **Branch**: `stage-a-oauth-prompt`
   - **Git Parent Branch**: `stage-a-docs-operations`
   - **PR Base Branch**: `main`
   - **Original Issue**: [#202](https://github.com/AndreiBozantan/svelte-axum-template/issues/202)
   - **Description**: Appends `prompt=select_account` to the Google OAuth authorization URL to allow clean user account switching.

9. **[PR #292](https://github.com/AndreiBozantan/svelte-axum-template/pull/292)**
   - **Branch**: `stage-a-docs-plan-update`
   - **Git Parent Branch**: `stage-a-oauth-prompt`
   - **PR Base Branch**: `main`
   - **Original Issue**: N/A (Meta stabilization plan documentation update)
   - **Description**: Updates the main `stabilization-plan.md` checklist with PR links and recommended merge order.
