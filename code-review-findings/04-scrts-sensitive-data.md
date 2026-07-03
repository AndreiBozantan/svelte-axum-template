# 04 — Secrets & Sensitive Data

> The `scrts` filename is intentional: `.gitignore` has a `*secret*` pattern, so spelling
> it out would git-ignore this file. Don't "fix" the name.

Handled well: no secrets committed, OAuth secret is masked in `Debug`/serialization, emails
are hashed before logging, passwords are never logged. Findings are minor.

---

## 4.1 — Full settings struct (including DB URL) is logged at startup

- **Severity:** Minor
- **Location:** `backend/server.rs:79-84` — `info!("configs: {:#?}", &settings)` plus
  individual `sql_url` line.
- **Finding:** The OAuth client secret is redacted by the custom `Debug` impl (good), but the
  entire `AppSettings` is dumped to logs at startup, including `database.url`. Today the DB
  URL is a local SQLite path, but env-var overrides could put credentials there in other
  deployments, and dumping full config is a habit that leaks the next secret added.
- **Risk:** Future secret leakage into logs; noisy startup logs.
- **Recommendation:** Log only the specific non-sensitive fields you need. Ensure any new
  secret-bearing field gets the same redaction treatment as `google_client_secret`.

---

## 4.2 — CSRF token hashes are logged on mismatch

- **Severity:** Minor
- **Location:** `backend/platform/identity/oauth/oauth_service.rs:257-264`
  (`csrf_token_mismatch` logs `expected_hash` and `actual_hash`).
- **Finding:** These are SHA-256 hashes of single-use CSRF tokens, not the tokens themselves,
  so exposure is low. Still, logging both the expected and actual value of a security token
  (even hashed) is more than needed for debugging and could aid an attacker correlating
  attempts.
- **Risk:** Low.
- **Recommendation:** Log only that a mismatch occurred (maybe a short prefix), not both full
  hashes.

---

## 4.3 — JWT secret file: good handling; document rotation

- **Severity:** Minor (informational)
- **Location:** `backend/platform/shared/jwt.rs:169-220`.
- **Finding:** The JWT secret is generated with a CSPRNG (`SysRng`), 32 bytes, written
  atomically with `0o600` perms via temp-file + rename. Solid. However: (a) there is no key
  rotation story — a single static HMAC key signs all tokens indefinitely; (b) if the file is
  lost/regenerated, all sessions silently invalidate. The project-review explicitly asks about
  "key rotation readiness."
- **Risk:** No graceful key rotation; compromise of the key requires a hard cutover.
- **Recommendation:** Support a key-id (`kid`) header and a small set of accepted decoding
  keys to allow overlap during rotation. At minimum, document the rotation procedure and the
  effect of losing/rotating the secret.

---

## 4.4 — `.env.example` and `.gitignore` are complete; verified

- **Severity:** Informational
- **Location:** `.gitignore` (ignores `*local*`, `*secret*`, `.env`, `data/db.sqlite*`),
  `.env.example`, `data/configs.local.toml` confirmed git-ignored.
- **Finding:** No secrets are committed. `.env.example` contains only non-sensitive
  placeholders. `configs.local.toml` (the documented place for secrets) is git-ignored and
  the committed copy is empty. Good. No change needed.
