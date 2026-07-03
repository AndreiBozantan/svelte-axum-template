# 20 — Business Logic Correctness

Auth/token state machine is carefully built and well-tested. The correctness issues are around
identity/tenant assumptions and unenforced domain invariants.

---

## 20.1 — "Admin" identity is inconsistent across the system

- **Severity:** Important
- **Location:** seed user id **0** as system admin (`migrations/01_initial_schema.sql:52-53`),
  CLI `create-admin`/`bootstrap_admin_from_env` update **user_id 0**
  (`backend/cli.rs:162-173,210-219`), but frontend treats **id 1** as admin
  (`AppState.svelte.ts:26`), and there is no `role` column at all.
- **Finding:** Three different notions of "admin": the seeded system user is id 0 (tenant 1), the
  CLI writes admin credentials onto id 0, and the frontend thinks id 1 is admin. None of them is
  backed by a role/permission the backend enforces. The invariant "an admin is X" is not defined in
  one place.
- **Risk:** Confusing and incorrect privilege logic; a real admin control built on this would be
  wrong from the start. Cross-listed with [02](02-authorization-access-control.md) and
  [09](09-frontend-code-quality.md).
- **Recommendation:** Define admin as an explicit `role`/`is_admin` on `users`, set it on the seed
  admin (id 0) and via the CLI, expose it in `UserInfo`, and enforce it server-side. Remove the
  frontend's id-based guess.

---

## 20.2 — Registration always assigns `tenant_id = 0` and `status = Active`, bypassing onboarding
- **GitHub Issue:** [#214](https://github.com/AndreiBozantan/svelte-axum-template/issues/214)

- **Severity:** Minor
- **Location:** `backend/platform/identity/auth/auth_service.rs:101-122` (`register`),
  `oauth_service`/`login_oauth` → `tenant_id = 0`.
- **Finding:** Every registration hardcodes tenant 0 and `Active`. The `Onboarding` status exists
  in the model/schema but is never used — there's no onboarding state machine, and no way to place
  a new user into a specific tenant/org. The domain has states (`onboarding/active/suspended/
  archived`) that the code never transitions between.
- **Risk:** The status enum implies a lifecycle that isn't implemented; suspended/archived aren't
  enforced (see [01](01-authentication-session.md) 1.1). Illegal/unused states are reachable only
  by direct DB edits.
- **Recommendation:** Either implement the lifecycle (onboarding → active, suspend/archive
  transitions with enforcement) or trim the enum to what's actually used. Don't ship states with no
  transitions or checks.

---

## 20.3 — SSO account linking auto-links by email with no verification step
- **GitHub Issue:** [#213](https://github.com/AndreiBozantan/svelte-axum-template/issues/213)

- **Severity:** Important
- **Location:** `backend/platform/identity/users/users_db.rs:277-316` (`link_sso_user`
  `ON CONFLICT(email) DO UPDATE SET sso_provider/sso_id`), `oauth_service.rs` /
  `auth_service::login_oauth`.
- **Finding:** When a Google login arrives for an email that already exists as a password account,
  the code silently links the Google identity to that account (overwriting `sso_provider`/`sso_id`)
  and logs the user in. Google's `verified_email` is checked (good), so the email is proven to
  belong to the Google account — which makes this *reasonably* safe — but it means: (a) a password
  user's account can be taken over via Google if an attacker controls a Google account with the
  same verified email (not possible for Gmail, but possible for Google Workspace domains where the
  domain admin controls addresses); (b) `sso_id` is overwritten on every login, so a second Google
  account with the same email (edge case) would relink.
- **Risk:** Account-linking is a classic auth pitfall. The `verified_email` gate mitigates the
  SSO→password direction, but the reverse direction is exploitable: because password
  registration never verifies email ownership, an attacker can pre-register a victim's email
  and wait for the victim to "sign in with Google" — the link lands on the attacker-controlled
  row with the attacker's password intact. See [01](01-authentication-session.md) **1.8** for
  the full pre-hijacking write-up; that finding supersedes the "reasonably safe" assessment
  above.
- **Recommendation:** Fix together with 1.8: require email verification before a password
  account is linkable (or reset `password_hash` + revoke sessions on link), and make
  auto-linking an explicit, documented product decision — consider requiring the user to be
  logged in (or to confirm) before linking a new SSO identity to an existing password account.

---

## 20.4 — Edge cases (empty/duplicate/unicode/bounds) mostly handled; gaps noted

- **Severity:** Minor
- **Location:** `common.rs:19-34` (email parse/normalize), `api.rs:225-240` (pagination clamp),
  register validation.
- **Finding:** Good: email is trimmed + lowercased + validated; pagination `limit` is clamped to
  `1..=200` and `offset` to `>= 0`; duplicate registration is caught by the unique constraint → 409.
  Gaps: password has a min but no max length (DoS, see [03](03-input-validation-injection.md) 3.1);
  names are unbounded/unnormalized; there's no check that `limit`/`offset` multiplication or very
  large `offset` is sane (offset pagination degrades on large offsets).
- **Recommendation:** Add the password max-length and name bounds. Otherwise edge handling is solid.

---

## 20.5 — Partial-failure consistency in multi-step flows

- **Severity:** Minor (cross-listed with 10.2)
- **Location:** `auth_service.rs` login/refresh sequences.
- **Finding:** Refresh's revoke-old + insert-new and login's verify + counter-update + rehash are
  not transactional, so a crash mid-sequence can leave inconsistent state (revoked-but-not-replaced
  token, or reset counter without rehash). Low probability; see [10](10-database-data-layer.md) 10.2
  for the fix.
