# 13 — Error Handling & Resilience

Error handling is a strong point: typed `thiserror` enums per module, `From` conversions to a
single `api::Error`, a global catch-panic layer, and internal details are not leaked to
clients. Findings are about timeouts, graceful shutdown completeness, and a couple of swallowed
errors.

---

## 13.1 — No timeout on inbound request handling or DB queries
- **GitHub Issue:** [#199](https://github.com/AndreiBozantan/svelte-axum-template/issues/199)

- **Severity:** Important
- **Location:** `backend/router.rs:56-73` (no `TimeoutLayer`); `backend/platform/shared/db.rs`
  (no per-query timeout; only `busy_timeout` for lock contention).
- **Finding:** There is no request timeout layer, so a slow handler or a stuck DB query can hold
  a connection/task indefinitely. The outbound Google userinfo call *does* set a 10s timeout
  (`oauth_service.rs:284`) — good — but inbound requests and DB operations have no upper bound.
  Argon2 hashing (intentionally slow) with no request timeout compounds this under load.
- **Risk:** Resource exhaustion / task pile-up under slow-loris-style or overload conditions.
- **Recommendation:** Add `tower_http::timeout::TimeoutLayer` at the router level (e.g. 30s), and
  consider a statement timeout for DB queries. Keep the OAuth call's explicit timeout.

---

## 13.2 — OAuth token-exchange HTTP call has no explicit timeout
- **GitHub Issue:** [#199](https://github.com/AndreiBozantan/svelte-axum-template/issues/199)

- **Severity:** Minor
- **Location:** `backend/platform/identity/oauth/oauth_service.rs:267-276`
  (`client.exchange_code(...).request_async(&oauth_client)` — the `oauth_client` is built with
  defaults; only the *userinfo* GET at `:284` sets a 10s timeout).
- **Finding:** The authorization-code→token exchange with Google uses a freshly built reqwest
  client with no timeout, unlike the userinfo call. A hung Google token endpoint would block the
  callback handler indefinitely (until the OS/socket gives up).
- **Recommendation:** Build the OAuth reqwest client with a connect/read timeout (mirror the 10s
  used for userinfo), or reuse `context.http_client` which is centrally configured.

---

## 13.3 — Graceful shutdown only listens for Ctrl-C, not SIGTERM
- **GitHub Issue:** [#200](https://github.com/AndreiBozantan/svelte-axum-template/issues/200)

- **Severity:** Important (for container deployment)
- **Location:** `backend/server.rs:158-163` (`shutdown_signal` awaits `tokio::signal::ctrl_c()`
  only).
- **Finding:** Containers and orchestrators send **SIGTERM** on stop/rollout, not SIGINT. The
  shutdown handler only awaits `ctrl_c()` (SIGINT), so on `docker stop`/Kubernetes termination
  the process won't drain in-flight requests gracefully — it'll be SIGKILL'd after the grace
  period. The review criteria explicitly ask for "graceful shutdown on SIGTERM."
- **Risk:** In-flight requests dropped on every deploy/rollout; no clean connection draining.
- **Recommendation:** Also await a `tokio::signal::unix::signal(SignalKind::terminate())` future
  and trigger graceful shutdown on either signal.

---

## 13.4 — Background cleanup tasks have no restart/panic handling
- **GitHub Issue:** [#231](https://github.com/AndreiBozantan/svelte-axum-template/issues/231)

- **Severity:** Minor
- **Location:** `backend/server.rs:110-138` (two `tokio::spawn` loops).
- **Finding:** The refresh-token and rate-limiter cleanup tasks are spawned and run forever, but
  if either task's future panics, the task dies silently and cleanup stops with no log or restart.
  The DB-cleanup task logs errors per-iteration (good), but a panic (vs `Err`) would kill it.
- **Recommendation:** Wrap the loop bodies so a panic is caught/logged and the loop continues, or
  supervise the tasks (log on join and respawn). At minimum log if a task exits.

---

## 13.5 — Health check is liveness-only; no readiness distinction
- **GitHub Issue:** [#234](https://github.com/AndreiBozantan/svelte-axum-template/issues/234)

- **Severity:** Minor
- **Location:** `backend/router.rs:107-137` (`/health` runs `SELECT 1`).
- **Finding:** `/health` verifies DB connectivity (good — it's more than a bare liveness probe).
  But there's a single endpoint; orchestrators often want separate liveness (process up) and
  readiness (dependencies ok) probes. Also the `panic=true` query param is a deliberate
  crash-test hook exposed on a public endpoint — fine for a template but should be gated to
  non-prod. See [14](14-logging-observability.md).
- **Recommendation:** Consider splitting `/health` (liveness) from `/ready` (DB check), and gate
  the panic hook to non-production.

---

## 13.6 — Graceful degradation when the DB is down

- **Severity:** Minor
- **Location:** startup `common.rs:79-97` (fails fast if DB can't connect — good);
  request paths return `500 internal_error` on DB errors (good, no leak).
- **Finding:** Startup correctly fails fast on DB-connect failure. At request time, DB errors
  become clean `500`s. There's no retry/backoff for transient DB errors, which for local SQLite
  is acceptable (busy_timeout handles lock contention). No change required beyond awareness.
