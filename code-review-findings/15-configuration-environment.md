# 15 — Configuration & Environment

The layered config system (defaults → common → env-specific → local → env vars) is well
designed and the `default()` env is a safe `production`. But the committed **common** config
overrides that to `development`, and there is no fail-fast validation of required settings.

---

## 15.1 — Committed `configs.common.toml` forces `env = "development"`

- **Severity:** Critical
- **Location:** `data/configs.common.toml:1-5` (`env = "development"`, `log_directives =
  "debug,..."`), loaded as layer 1 for *all* environments in
  `backend/platform/shared/config.rs:160-198`; `migrations.rs:60-81` seeds `test-data.sql`
  and enables verbose behavior when `is_dev_env()`.
- **Finding:** `AppSettings::default()` correctly defaults `env` to `production`
  (`config.rs`/`ServerSettings::default`), but `configs.common.toml` — which is loaded before the
  env-specific file and is committed — sets `env = "development"` and debug logging. The
  environment is only corrected if `configs.production.toml` is present *and* actually loaded.
  The production-file auto-creation logic keys off `partial_config.server.env`, which at that
  point already reads `development` from common — so in a deployment that ships the repo's `data/`
  without explicitly forcing `APP__SERVER__ENV=production`, **the app can run in development mode
  in production**: debug logs, and (if the seed file were present) test-data seeding.
- **Risk:** Verbose/debug logging in prod, potential test-data seeding, and any other
  `is_dev_env()`-gated behavior silently active in production. This is the highest-impact config
  issue.
- **Recommendation:** Do not set `env` in `configs.common.toml` at all (leave it to the
  env-specific file / env var, falling back to the safe `production` default). Or invert the
  precedence so the deployment must opt *into* development. Add a startup assertion that logs the
  effective env prominently and refuses to seed test data unless `env` is explicitly dev/test.

---

## 15.2 — No fail-fast validation of required configuration at startup

- **Severity:** Important
- **Location:** `backend/platform/shared/config.rs:150-201` (`AppSettings::new` just deserializes
  with defaults); OAuth config is only *warned* about, not enforced
  (`oauth_service.rs:171-175` `check_oauth_config` logs a warning).
- **Finding:** Missing/invalid required config does not stop startup. Every field has a `#[serde(default)]`,
  so an entirely empty config produces a running server with default secrets/paths. OAuth
  misconfiguration logs a warning and continues; a login attempt then fails at runtime rather
  than at boot. There is no validation that, e.g., in production the JWT secret is strong, the DB
  URL is set, or OAuth (if enabled) is complete.
- **Risk:** Misconfigured deployments start "successfully" and fail later in user-facing paths.
- **Recommendation:** Add a `validate()` step in `AppSettings::new` that fails fast on invalid/
  missing required values (especially in production): enforce OAuth completeness if any OAuth
  field is set, validate the DB URL, and assert the env is one of the known values.

---

## 15.3 — Production config file is auto-created on first run with defaults

- **Severity:** Minor
- **Location:** `backend/platform/shared/config.rs:192-198`.
- **Finding:** In production, if `configs.production.toml` doesn't exist, the app writes one from
  the merged settings. Convenient, but it means the running config depends on filesystem state in
  the data volume and can silently differ from what's in the repo. Combined with 15.1, the
  auto-created file could bake in `development` values if the common layer leaked them.
- **Recommendation:** Keep the convenience but log loudly what was written, and derive it from
  known-safe production defaults rather than whatever the partial merge produced.

---

## 15.4 — Not all config keys are documented

- **Severity:** Minor
- **Location:** `README.md:38-45`, `docs/` (no complete config reference); config structs in
  `config.rs`.
- **Finding:** README explains the layering and OAuth, but there's no single reference listing
  every key (`database.min/max_connections`, `store_temp_tables_in_memory`,
  `write_busy_timeout_seconds`, rate-limiter fields, token lifetimes) and its meaning/default.
- **Recommendation:** Add a config reference table (or doc-comment each field and generate one).

---

## 15.5 — Dev/prod separation and env-var override mechanism are sound; verified

- **Severity:** Informational
- **Location:** `config.rs:150-201`, `configs.production.toml`, `configs.development.toml`.
- **Finding:** The `APP__SECTION__KEY` env-var override with `__` separator is clean and
  documented, per-env files are separate, and the local file is git-ignored for secrets. The
  layering design itself is good — the problem is purely the `env` value baked into the common
  layer (15.1).
