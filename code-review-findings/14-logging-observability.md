# 14 — Logging & Observability

Structured logging with `tracing` is used consistently, security events are audited (login
attempt/success, refresh, SSO), and PII is hashed before logging. The main gaps are request-ID
correlation, metrics, and a couple of over-logging spots.

---

## 14.1 — No request-ID / correlation ID threaded through logs

- **Severity:** Important
- **Location:** `backend/router.rs:56-69` (`TraceLayer` builds a span with method/uri/ip/ua but
  no request id); `docs/api/conventions.md:211-218` documents `X-Request-ID` as a *target*
  convention that is "not implemented yet."
- **Finding:** There is no `X-Request-ID` generation/propagation. Logs cannot be correlated to a
  single request across the multiple log lines a request emits (attempt, success, error). For a
  SaaS with support obligations, this is a real operability gap (and the docs already promise it).
- **Recommendation:** Add `tower_http::request_id` (set/propagate `X-Request-ID`) and include it
  in the tracing span so all lines for a request share the id. Return it in responses so clients
  can quote it.

---

## 14.2 — No application metrics exposed

- **Severity:** Important
- **Location:** whole backend — no `/metrics`, no request/latency/error counters.
- **Finding:** There are no metrics (request count, latency histogram, error rate, auth
  failures). Observability is logs-only. For "10× traffic" readiness and incident response, you
  need at least basic RED metrics.
- **Recommendation:** Add a metrics exporter (e.g. a Prometheus `/metrics` endpoint via a
  `tower` metrics layer). Keep it proportionate — request rate/latency/error and auth-failure
  counters are enough to start.

---

## 14.3 — Full config dump at startup (cross-listed)

- **Severity:** Minor
- **Location:** `backend/server.rs:79-84`.
- **Finding:** `info!("configs: {:#?}", &settings)` and an explicit `sql_url` log line. Secret is
  redacted, but this is verbose and risks leaking future secret fields. See
  [04](04-scrts-sensitive-data.md) 4.1.
- **Recommendation:** Log a curated subset.

---

## 14.4 — Public `/health?panic=true` crash hook is available in production

- **Severity:** Minor
- **Location:** `backend/router.rs:101-143` (`HealthCheckQuery { panic }` → `healthy_panic()`).
- **Finding:** Anyone can trigger a panic (caught by the panic layer, returns 500) on the public
  health endpoint in any environment. It's a deliberate resilience-demo hook, and the panic is
  caught, but it lets unauthenticated callers generate error-log noise / exercise the panic path
  at will in prod.
- **Recommendation:** Gate the panic branch behind a non-production check (`ctx.is_prod_env()`)
  or a debug feature flag.

---

## 14.5 — Log levels and directives are sensible; verified

- **Severity:** Informational
- **Location:** `config.rs:132` (prod default `info,tower_http=warn,axum=warn`),
  `data/configs.production.toml:5`.
- **Finding:** Production log directives are appropriately quiet; dev is `debug`. Error responses
  log at `error!` for 5xx and `info!` for client errors (`api.rs:160-169`) — correct level
  discipline. PII (emails) is SHA-256 hashed before logging in auth/oauth paths. Good.
