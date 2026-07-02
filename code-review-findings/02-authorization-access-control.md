# 02 — Authorization & Access Control

This is the weakest area relative to the "production SaaS" bar. Authentication is enforced;
**authorization is essentially absent.**

---

## 2.1 — `GET /api/users` discloses every user in the shared default tenant

- **Severity:** Critical
- **Location:** `backend/platform/identity/users/users_api.rs:60-92` (`list_users`),
  `backend/platform/identity/users/users_db.rs:224-275` (`list_by_tenant`),
  `backend/platform/identity/auth/auth_service.rs:101-122` (`register`, uses
  `TenantId(0)`), `:169-184` (`login_oauth`, uses `DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS = 0`).
- **Finding:** Every self-signup and every Google-SSO user is created under `tenant_id = 0`
  (the "Default" tenant). `list_users` returns all users for the caller's tenant with no
  role check. Therefore **any authenticated ordinary user can call `GET /api/users` and
  enumerate the email addresses of every other self-signup/SSO user on the platform.**
- **Risk:** Mass PII / email disclosure across unrelated accounts. In a multi-tenant SaaS
  this is a serious data-isolation and privacy failure (and a spam/phishing target list).
  The "tenant isolation" that the code appears to provide is illusory because all public
  users share one tenant.
- **Recommendation (pick per product intent):**
  - If users are *not* meant to see each other: gate `list_users` behind an admin/role
    check (see 2.2) and return `404`/`403` otherwise.
  - If the platform is genuinely multi-tenant: give each self-signup user their own tenant
    (or organization) instead of the shared tenant 0, so tenant scoping actually isolates.
  - Either way, add a test asserting a normal user cannot enumerate other users.

---

## 2.2 — No role/authorization model exists; "admin" is not enforced anywhere on the backend

- **Severity:** Critical
- **Location:** whole `backend/platform/identity`; `migrations/01_initial_schema.sql`
  (no role/permission column on `users`); `backend/router.rs:41-45` (only auth middleware,
  no authz layer).
- **Finding:** There is no concept of roles or permissions in the data model or the API.
  The only distinction is authenticated vs not. The CLI can create an "admin" by updating
  user id 0's credentials, but nothing marks a user as privileged, and no endpoint checks
  for privilege. The frontend invents an `isAdmin` (`user.id === 1`) that has no backend
  counterpart (and is wrong — see 09).
- **Risk:** Any future admin/internal endpoint has nothing to gate on. Today it means
  every authenticated user is equally privileged, which combined with 2.1 is the disclosure
  vector.
- **Recommendation:** Add an explicit `role` (or `is_admin`) column to `users`, thread it
  into `TokenClaims`, and add an extractor/middleware that enforces roles per route. Protect
  `list_users` (and any future admin endpoints) with it. Design this before adding more
  endpoints, not after.

---

## 2.3 — `/api/users/me` trusts `tenant_id` and `sub` from the JWT without re-validation

- **Severity:** Minor (acceptable, documented for completeness)
- **Location:** `backend/platform/identity/users/users_api.rs:105-121` (`user_info`),
  `backend/platform/shared/jwt.rs:78-88`.
- **Finding:** `user_info` reads `tenant_id`/`user_id` from the signed claims and looks the
  user up scoped by both. This is fine — the JWT is signed and the lookup is tenant-scoped.
  Noting it because it is the pattern the whole API relies on: correctness depends entirely
  on the signing key staying secret and the claims being set correctly at issuance. No change
  required.

---

## 2.4 — IDOR surface is currently small but unguarded by design

- **Severity:** Minor (forward-looking)
- **Location:** `users_db.rs` queries are consistently `WHERE ... AND tenant_id = ?`.
- **Finding:** Existing queries are tenant-scoped, which is good. But there is no
  per-resource ownership check pattern established (e.g. "user X may only read/modify
  resource owned by X"). The moment a resource with a path `id` is added, developers have
  no shared helper to enforce ownership and will likely re-derive it ad hoc.
- **Recommendation:** Establish an ownership-check convention now (a helper that verifies
  `resource.tenant_id == claims.tenant_id` *and* ownership where applicable) so new endpoints
  inherit it. Return `404` on failure per `conventions.md` §6.
