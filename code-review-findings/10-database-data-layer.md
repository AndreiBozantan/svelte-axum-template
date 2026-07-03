# 10 — Database & Data Layer

Schema is reasonable, queries are parameterized and tenant-scoped, WAL + foreign keys +
busy_timeout are set, and there's a working expired-token cleanup task. Findings concern
missing pragmas, transaction gaps, and the `email UNIQUE` vs multi-tenant tension.

---

## 10.1 — `synchronous` pragma not set; durability under WAL is at SQLite default
- **GitHub Issue:** [#229](https://github.com/AndreiBozantan/svelte-axum-template/issues/229)

- **Severity:** Important
- **Location:** `backend/platform/shared/db.rs:8-35`.
- **Finding:** Connect options set `journal_mode = WAL`, `foreign_keys`, and `busy_timeout`,
  but never set `PRAGMA synchronous`. With WAL, the safe/common setting is
  `synchronous = NORMAL`; the SQLite compiled default may be `FULL` (slower) and, depending on
  driver, could be left in a state you didn't choose. The review criteria explicitly ask that
  `synchronous` be configured.
- **Risk:** Either unnecessary fsync cost (FULL) or, if ever lowered without WAL, durability
  loss. Ambiguity is the problem — it should be explicit.
- **Recommendation:** Set `.pragma("synchronous", "NORMAL")` explicitly in the connect options
  (correct pairing with WAL), and document the durability trade-off.

---

## 10.2 — Multi-operation flows are not wrapped in transactions

- **Severity:** Important
- **Location:** `backend/platform/identity/auth/auth_service.rs:150-166` (verify → update
  failed count / reset count → rehash → issue session, as separate awaited statements),
  `:186-211` (`issue_session`: insert refresh token after generating), `:224-268` (`refresh`:
  revoke old + insert new as separate statements).
- **Finding:** Several logically-atomic sequences run as independent statements without a
  transaction. Example: in `refresh`, `try_revoke_active_by_jti` (revokes old) and
  `tokens.create` (inserts new) are separate; a crash or error between them can revoke the old
  token without persisting the new one, leaving the user unable to refresh (they'd have to log
  in again). Login's counter-reset + rehash are also non-atomic.
- **Risk:** Partial-failure inconsistency (orphaned/lost token rows, stuck counters). Low
  probability, but the review criteria call for transactions "where multiple operations must be
  atomic."
- **Recommendation:** Wrap the rotate-refresh sequence (revoke old + insert new) in a single
  `sqlx` transaction. Same for any future multi-write business operation.

---

## 10.3 — `email UNIQUE` globally conflicts with the multi-tenant model
- **GitHub Issue:** [#209](https://github.com/AndreiBozantan/svelte-axum-template/issues/209)

- **Severity:** Important
- **Location:** `migrations/01_initial_schema.sql:38-40` (`UNIQUE(email)`,
  `UNIQUE(tenant_id, id)`, `UNIQUE(sso_provider, sso_id)`).
- **Finding:** `email` is globally unique across all tenants. If the platform is truly
  multi-tenant, the same person cannot exist in two tenants — usually you want
  `UNIQUE(tenant_id, email)`. Combined with all public users sharing tenant 0
  (see [02](02-authorization-access-control.md)), the data model hasn't decided whether it is
  single-tenant-with-a-tenant-column or genuinely multi-tenant. `link_sso_user` relies on the
  global `ON CONFLICT(email)`, so changing this touches SSO linking.
- **Risk:** Architectural ambiguity that will force a painful migration later; SSO-linking
  logic is coupled to the global-unique assumption.
- **Decided:** the maintainer chose **real multi-tenancy with many-to-many memberships**
  (see [docs/design/authorization.md](../docs/design/authorization.md)). Under that model users are
  **global accounts** and the user↔tenant link moves to a `memberships` table — so the
  global `UNIQUE(email)` is actually *correct* (one account, many tenants) and this tension
  resolves without a composite key. The work is: drop the single `tenant_id` FK from `users`,
  add `memberships`, and rework `link_sso_user` (SSO links a global user, not a tenant-scoped
  one). Tracked in the authorization design's build order, backend plan Phase 0.

---

## 10.4 — `updated_at` trigger causes double writes / recursion risk; and `RETURNING` may not reflect it
- **GitHub Issue:** [#259](https://github.com/AndreiBozantan/svelte-axum-template/issues/259)

- **Severity:** Minor
- **Location:** `migrations/01_initial_schema.sql:10-15,44-50` (AFTER UPDATE triggers that
  `UPDATE ... SET updated_at = CURRENT_TIMESTAMP`).
- **Finding:** The `updated_at` triggers issue a second `UPDATE` after every update. App-level
  updates already `SET updated_at = CURRENT_TIMESTAMP` explicitly (e.g. `users_db.rs:327,353`),
  so the trigger fires redundantly on top of the explicit set (an extra write per update). SQLite
  won't infinitely recurse (recursive triggers are off by default), but this is wasteful and
  means the two mechanisms can disagree on the exact timestamp.
- **Recommendation:** Pick one mechanism — either the trigger *or* explicit `updated_at` in the
  app queries, not both. The trigger alone is cleaner (can't be forgotten).

---

## 10.5 — Timestamps stored as `DATETIME` text via `CURRENT_TIMESTAMP` (UTC) but compared against `naive_utc()`

- **Severity:** Minor
- **Location:** `refresh_tokens` (`issued_at`/`expires_at`/`revoked_at` as `NaiveDateTime`),
  `tokens_service.rs`, `auth_service.rs:289-291` (`Utc::now().naive_utc()` compared to
  `revoked_at`), `tokens_db.rs:61-63,146-148` (epoch written as `naive_utc`).
- **Finding:** SQLite `CURRENT_TIMESTAMP` yields UTC text; the app uses `NaiveDateTime` and
  `Utc::now().naive_utc()` consistently, so comparisons are correct *as long as* every writer
  uses UTC. It works today, but naive timestamps carry no timezone and one non-UTC writer would
  silently corrupt lockout/grace-period math. The review criteria specifically call out
  timezone/clock-skew correctness.
- **Recommendation:** Keep everything UTC (it is) and add a comment/invariant that all DB
  timestamps are UTC-naive. Consider storing explicit ISO-8601 UTC (`DateTime<Utc>`) to make the
  contract self-documenting.

---

## 10.6 — Cascade deletes are configured; anonymization/lifecycle is not
- **GitHub Issue:** [#240](https://github.com/AndreiBozantan/svelte-axum-template/issues/240)

- **Severity:** Minor
- **Location:** `migrations/01_initial_schema.sql:41,64` (`ON DELETE CASCADE` on
  users→tenants and refresh_tokens→users).
- **Finding:** Cascades are intentional and correct (deleting a user removes their refresh
  tokens; deleting a tenant removes its users). But there is no account-deletion or
  anonymization endpoint/flow at all, and no soft-delete story — the `status = 'archived'`
  value exists but nothing sets or acts on it. For a SaaS with paying customers, data-lifecycle
  (GDPR-style deletion/anonymization) is unaddressed.
- **Recommendation:** Define the account-deletion/anonymization policy and implement at least a
  path to archive/anonymize a user. Decide soft vs hard delete per `conventions.md`'s own open
  question.

---

## 10.7 — Connection pool sizing and backup strategy
- **GitHub Issue:** [#229](https://github.com/AndreiBozantan/svelte-axum-template/issues/229)

- **Severity:** Minor
- **Location:** `db.rs:18-21`, `config.rs:48-58` (max 5 / min 2 connections).
- **Finding:** For SQLite with WAL, multiple writer connections still serialize on the write
  lock; 5 connections is fine for reads. No connection acquire-timeout is set (relies on
  `busy_timeout` for lock contention only). There is no backup/recovery strategy for the SQLite
  file (the review asks for one) — the Docker volume is the only durability boundary.
- **Recommendation:** Add an acquire timeout to the pool. Document a backup approach
  (e.g. `VACUUM INTO` / litestream-style WAL shipping) since the DB is a single file in a volume.
