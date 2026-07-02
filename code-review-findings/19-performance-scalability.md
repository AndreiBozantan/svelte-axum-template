# 19 — Performance & Scalability

No egregious hot-path problems, and mimalloc is the global allocator. The main scalability
ceiling is inherent to single-file SQLite; the main code smell is Argon2 on the async executor.

---

## 19.1 — Argon2 hashing runs on the async runtime without `spawn_blocking`

- **Severity:** Important
- **Location:** `backend/platform/shared/crypto.rs:23-42` (`hash_password`/`verify_password`),
  called inline in `auth_service.rs` `register`/`login`/`update_password_hash`.
- **Finding:** Argon2id with `m=19456KB, t=2, p=1` takes tens of milliseconds of pure CPU per
  call, executed directly on a Tokio worker thread. Under concurrent logins/registrations this
  blocks async workers and can starve the executor (every login also does a *second* hash via the
  dummy-hash timing defense). The review criteria explicitly flag "heavy CPU work on the async
  executor."
- **Risk:** Latency spikes and reduced throughput under auth load; a burst of logins can stall
  unrelated requests sharing the worker pool.
- **Recommendation:** Run hashing/verification inside `tokio::task::spawn_blocking` (or a dedicated
  rayon pool). This keeps the async workers free for I/O.

---

## 19.2 — `list_users` runs a `COUNT(*)` on every call

- **Severity:** Minor
- **Location:** `backend/platform/identity/users/users_db.rs:259-264`.
- **Finding:** Each list request issues a second query, `SELECT COUNT(*) ... WHERE tenant_id = ?`,
  to populate `total`. For the shared tenant 0 (all public users), this count grows unbounded and
  is recomputed per request. Two round-trips per list call. Tied to the offset-pagination choice
  (see [11](11-api-design.md) 11.2).
- **Risk:** Grows with user count; unnecessary work if `total` isn't needed by clients.
- **Recommendation:** Move to cursor pagination (drops the count), or make `total` opt-in, or cache
  it. There's an index on `tenant_id` (good), so the count is not catastrophic, but it's avoidable.

---

## 19.3 — Rate-limiter key maps grow unbounded between cleanup ticks

- **Severity:** Minor
- **Location:** `backend/platform/shared/rate_limiter.rs` (governor keyed by client-IP string),
  cleanup task `backend/server.rs:123-137` (`retain_recent` every 15 min).
- **Finding:** The governor stores per-key state keyed by the (spoofable) client-IP string. With
  spoofable `X-Forwarded-For` (see [05](05-http-transport-security.md) 5.3), an attacker can
  create unbounded distinct keys, growing the map until the 15-minute `retain_recent` sweep. This
  is both a memory-growth vector and another reason to fix IP trust.
- **Risk:** Memory growth under a header-spoofing flood.
- **Recommendation:** Fix IP trust (5.3) so keys come from real peer addresses, bounding
  cardinality. Keep the periodic `retain_recent` sweep.

---

## 19.4 — Would it handle 10× traffic? — SQLite write serialization is the ceiling

- **Severity:** Minor (informational / architectural)
- **Location:** `db.rs` (single SQLite file, WAL), token writes on every login/refresh.
- **Finding:** Reads scale fine under WAL, but every login and every refresh performs writes
  (insert token, update counters), and SQLite serializes writers. At high auth throughput the
  single write lock becomes the bottleneck; `busy_timeout` will start causing latency. This is
  acceptable for a template and small deployments but is the first thing to hit at 10×.
- **Recommendation:** Document the expected scale ceiling. If higher write throughput is needed,
  the path is Postgres (the repo/query layer is reasonably abstracted, though `sqlx::query!` macros
  are SQLite-dialect-bound). No action needed now beyond setting expectations.

---

## 19.5 — Frontend bundle: no code-splitting/lazy loading; small app so low impact

- **Severity:** Minor
- **Location:** `frontend/src/AppPages.svelte.ts` (all pages imported eagerly), `vite.config.ts`.
- **Finding:** All page components and Font Awesome icons are imported statically, so the whole app
  ships in one bundle. The app is tiny, so this is fine today, but the pattern (eager import of all
  routes) won't scale to a large app, and Font Awesome is a heavy icon lib imported per-icon.
- **Recommendation:** Fine for now. If the app grows, lazy-load page components. Asset caching is
  already handled well (immutable long-cache for hashed assets, `no-cache` + ETag for index) in
  `assets.rs` — good.

---

## 19.6 — Asset serving (cache/ETag/compression)

- **Severity:** Minor
- **Location:** `backend/platform/shared/assets.rs:37-91`.
- **Finding:** ETag (sha256) with `If-None-Match` → 304, immutable long-cache for hashed static
  assets, `no-cache` for index — all correct. But responses are **not compressed** (no
  `CompressionLayer`), so HTML/JS/CSS are served uncompressed.
- **Recommendation:** Add `tower_http::compression::CompressionLayer` (gzip/br) for text assets and
  JSON responses.
