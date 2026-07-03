# Stabilization Master Plan

The single plan for taking the codebase from "reviewed template" to "solid, production-ready
platform to build an app on". It merges the former backend/frontend stabilization plans, the
authorization design, and the execution-order doc into one timeline. The numbered findings
files ([01](01-authentication-session.md)–[21](21-general-hygiene.md)) remain the evidence
base: links point to the finding with full context and the recommended fix, and each checkbox
can become one GitHub issue. Links carry section anchors (they open scrolled to the finding);
`cargo xtask check-md-links` validates every link and anchor repo-wide (runs in pre-commit
for staged `.md` files and in the docs CI workflow).

## Creating issues from this plan

Each checkbox is one issue, written to be executable by anyone — a contributor who has never
seen these planning docs, or an AI coding agent — without further clarification:

- **Title:** the checkbox text (without the links).
- **Body:** copy the linked finding section(s) **verbatim** — they carry the file paths
  (Location), the problem (Finding), why it matters (Risk), and the fix (Recommendation).
  For Stage B items, link the *design:* section(s) of
  [docs/design/authorization.md](../docs/design/authorization.md) — the design doc lives in
  the repo precisely so issues can reference it.
- **Acceptance criteria:** state observable behavior, not implementation — e.g. "login as a
  suspended user returns 403 with code `account_suspended`; their refresh token no longer
  works", not "add a status check".
- **Dependencies:** the stage ordering encodes them; if an item needs another to land first
  (e.g. anything consuming the mailer), name that issue in the body so it can be scheduled.
- **Definition of done, for every issue:** `cargo clippy --workspace --all-targets` clean and
  `cargo test` green; frontend checks/tests green when frontend files are touched;
  `cargo xtask openapi` re-run whenever an endpoint or DTO changes; API behavior follows
  `docs/api/conventions.md`; code style follows `AGENTS.md`.

## Guiding principles

- **Quality and architecture first.** The app is small, not deployed, and has no users. The
  goal is a clean, production-grade foundation — so prefer the *right* design over the
  backward-compatible one. Nothing in the current code is set in stone; refactors and rewrites
  are in scope wherever the existing organization falls short.
- **Breaking changes are free right now.** Schema, API, JWT-claim, and config changes cost
  nothing today and get more expensive with every deploy and user. Make them early.
- **Don't polish code you're about to rewrite.** The authorization refactor (Stage B) rewrites
  registration, `UserInfo`, the users endpoint, and `sample` — those get no cosmetic work
  before it.
- **Land small, individually green PRs.** Every step leaves `cargo clippy`, tests, and the
  frontend checks passing. The big refactor ships as ~a dozen reviewable PRs, not one branch.

## Architecture decisions (settled 2026-07-02)

These supersede the "pick a direction" recommendations in
[02 § 2.1/2.2](02-authorization-access-control.md#21--get-apiusers-discloses-every-user-in-the-shared-default-tenant) and [10 § 10.3](10-database-data-layer.md#103--email-unique-globally-conflicts-with-the-multi-tenant-model):

- **Tenancy: real multi-tenancy with many-to-many memberships.** Users are global accounts;
  `tenant_memberships` links user↔tenant with a role per tenant. `users.tenant_id` is dropped;
  the global `UNIQUE(email)` becomes *correct* (resolving the 10.3 tension).
- **Roles: DB-driven custom roles, tenant-scoped.** The permission *catalog* (the set of
  checkable actions) stays a fixed Rust enum — only role→permission groupings live in the DB.
  System roles (owner/admin/member/client) are seeded and immutable.
- **Entity access: generic ACL table (ReBAC-lite)** for restricted roles; broad roles see the
  whole tenant via RBAC (see the resolution rule below). Children inherit from parents.
- **Scaffolding: a real `projects` + `tasks` reference feature** in `backend/app/` replaces the
  `sample` placeholder and becomes the copy-me pattern for new features.
- **Environment selection:** `env` comes only from the process environment, never from a config
  file — [15 § 15.1/15.3](15-configuration-environment.md#151--committed-configscommontoml-forces-env--development),
  [16 § 16.1](16-containerization-deployment.md#161--configsproductiontoml-selection-depends-on-env-var-but-the-image-sets-none).

---

# Design docs

Durable decision-and-invariant references, kept under `docs/` (outside this review folder)
precisely so GitHub issues can link to their sections. Keep them short and stable — record
decisions, invariants, and rationale, **not** restatements of code that will drift (the
drifted-`conventions.md` finding [18 § 18.1](18-documentation-dx.md#181--docs-and-code-disagree-in-several-places) is the cautionary tale).
One exists; four more are created by plan items in the stages where their content gets
decided:

- **[docs/design/authorization.md](../docs/design/authorization.md)** — *exists.* The three
  authorization layers, resource-access resolution rule, data model, JWT claims, enforcement
  pattern. Backs the Stage B issues, and provides the shared authorization convention
  [02 § 2.4](02-authorization-access-control.md#24--idor-surface-is-currently-small-but-unguarded-by-design) asks for.
- **`docs/design/authentication.md`** — *written in Stage B* (that stage rewrites
  registration and adds the token flows). Contents: access/refresh token lifecycle (rotation,
  reuse/breach detection, concurrency grace period); cookie strategy (`__Host-`/`__Secure-`
  prefixes, HttpOnly, SameSite, why no token material in `localStorage`); the signed OAuth
  state-cookie design (PKCE verifier + CSRF hash) and the `prompt` choice; the **shared
  single-use hashed-token pattern** reused by email verification, password reset, and
  invitations; the mailer abstraction; account lifecycle states and where they are enforced
  (login + refresh). Much of this exists today only as code comments
  ([18 § 18.2](18-documentation-dx.md#182--almost-no-doc-comments-on-public-apis--complex-modules)); the verified descriptions in
  [01 § 1.5/1.7](01-authentication-session.md#15--refresh-issues-a-new-token-before-validating-the-token-hash-matches) are ready starting material.
- **`docs/design/operations.md`** — *started in Stage A, extended in Stage D/E.* Contents:
  the mandatory TLS-terminating proxy assumption and trusted-proxy header config;
  graceful-shutdown (SIGTERM) behavior; healthcheck/readiness semantics; SQLite operational
  choices (WAL, `synchronous=NORMAL`, pool timeouts), the backup strategy, and the accepted
  write-throughput ceiling with the Postgres migration path; pointer to the release/rollback
  workflow.
- **`docs/design/frontend.md`** — *started in Stage A, extended in Stage C.* Contents: the
  routing decision and its rationale; the rune-based `AppState` pattern; the "generated API
  client only, never raw `fetch`" rule; the capability model (`can(permission)` derived from
  `UserInfo`); the auth-refresh-manager contract (cross-linked to `authentication.md`).
- **`docs/config.md`** — *Stage E.* Reference rather than design: TOML layering and
  precedence (`common` → per-env → git-ignored `local`), every key with its default, and the
  env-only environment selection from Stage A — [15 § 15.4](15-configuration-environment.md#154--not-all-config-keys-are-documented).

## How the authorization design resolves existing findings

| Finding | Resolution |
| :-- | :-- |
| [02 § 2.1](02-authorization-access-control.md#21--get-apiusers-discloses-every-user-in-the-shared-default-tenant) (user enumeration) | `list_users` becomes a permission-gated, membership-scoped query |
| [02 § 2.2](02-authorization-access-control.md#22--no-roleauthorization-model-exists-admin-is-not-enforced-anywhere-on-the-backend) (no role model) | the RBAC layer |
| [02 § 2.4](02-authorization-access-control.md#24--idor-surface-is-currently-small-but-unguarded-by-design) (no ownership convention) | `authorize_resource` helper |
| [10 § 10.3](10-database-data-layer.md#103--email-unique-globally-conflicts-with-the-multi-tenant-model) (email UNIQUE vs tenancy) | global users + memberships |
| [20 § 20.1](20-business-logic-correctness.md#201--admin-identity-is-inconsistent-across-the-system) (admin identity) | role via membership; drop id-based guesses |
| [20 § 20.2](20-business-logic-correctness.md#202--registration-always-assigns-tenant_id--0-and-status--active-bypassing-onboarding) (unused lifecycle) | signup → tenant + owner membership; invite → `onboarding` member |
| [09 § 9.3](09-frontend-code-quality.md#93--isadmin-is-derived-from-userid--1-which-is-not-the-admin) (fake `isAdmin`) | real permissions from `/api/users/me` |
| [07 § 7.4](07-code-structure-architecture.md#74--emptyplaceholder-artifacts), [11 § 11.1](11-api-design.md#111--apiapisample--duplicated-path-prefix-ships-in-the-spec-and-client) (`sample`, `/api/api`) | retired by the projects/tasks reference feature |

---

# The staged plan

**The ordering principle: don't invest in code you're about to rewrite, and make the schema
change while it's still free.** The authorization refactor goes as early as its prerequisites
allow — after the cheap, independent work that protects and unblocks it.

## Stage A — Cheap, independent, protective (do first)

No ordering constraints among these; none is invalidated by the Stage B refactor.

Shipped frontend bugs:

- [ ] Failed login leaves Sign In permanently disabled — [09 § 9.1](09-frontend-code-quality.md#91--login-error-leaves-the-submit-button-permanently-disabled)
- [ ] `Logout.svelte` renders `[object Object]`; logout result ignored — [09 § 9.2](09-frontend-code-quality.md#92--logoutsvelte-renders-the-whole-user-object-instead-of-the-email)
- [ ] Silent bootstrap failure leaves a blank page — [09 § 9.10](09-frontend-code-quality.md#910--small-issues-dead-proxy-entry-unloaded-font-hardcoded-version-global-loading-flag-silent-bootstrap-failure)

Security fixes that don't touch the auth model:

- [ ] Enforce `user.status` on login and refresh; revoke tokens on suspend —
      [01 § 1.1](01-authentication-session.md#11--suspendedarchived-users-can-still-authenticate-and-refresh)
- [ ] Trusted-proxy handling: only honor `X-Forwarded-For`/`X-Real-IP` behind an explicit
      config flag — [01 § 1.3](01-authentication-session.md#13--login-rate-limiter-is-keyed-only-by-client-ip-not-by-account),
      [05 § 5.3](05-http-transport-security.md#53--global-rate-limit-key-can-be-spoofed-via-forwarding-headers), [19 § 19.3](19-performance-scalability.md#193--rate-limiter-key-maps-grow-unbounded-between-cleanup-ticks)
- [ ] Security response headers (nosniff, frame-ancestors, CSP, HSTS, Referrer-Policy) —
      [05 § 5.1](05-http-transport-security.md#51--no-security-headers-csp-x-content-type-options-x-frame-options-hsts-referrer-policy-permissions-policy)
- [ ] Request body limit + password/name max-length validation (hash-amplification DoS) —
      [03 § 3.1/3.2](03-input-validation-injection.md#31--no-request-body-size-limit-json-payloads-are-unbounded)
- [ ] Request timeout layer; timeout on the OAuth token exchange —
      [13 § 13.1/13.2](13-error-handling-resilience.md#131--no-timeout-on-inbound-request-handling-or-db-queries)
- [ ] Graceful shutdown on SIGTERM (container rollouts) —
      [13 § 13.3](13-error-handling-resilience.md#133--graceful-shutdown-only-listens-for-ctrl-c-not-sigterm)
- [ ] Start `docs/design/operations.md` with the mandatory TLS-terminating proxy assumption
      and the trusted-proxy header config (from the item above) —
      [05 § 5.2](05-http-transport-security.md#52--https-enforcement--httphttps-redirect-is-undocumented-and-unimplemented-in-app); outline in [Design docs](#design-docs)
- [ ] Google OAuth skips the consent/account-chooser screen: add `prompt=select_account` to
      the authorize URL — [01 § 1.10](01-authentication-session.md#110--google-oauth-flow-skips-the-consent--account-chooser-screen)

Configuration correctness:

- [ ] Environment selection: `env` only from the process environment; remove it from all TOML
      layers; set it in Dockerfile/compose/xtask — [15 § 15.1/15.3](15-configuration-environment.md#151--committed-configscommontoml-forces-env--development),
      [16 § 16.1](16-containerization-deployment.md#161--configsproductiontoml-selection-depends-on-env-var-but-the-image-sets-none)
- [ ] Fail-fast config validation at startup (esp. production) —
      [15 § 15.2](15-configuration-environment.md#152--no-fail-fast-validation-of-required-configuration-at-startup)

Decisions that gate later work:

- [ ] Frontend routing: adopt `svelte-spa-router` or finish the custom router (click
      interception, shared `pathToPage()`, 404 route) — **before any new pages exist**;
      record the decision + rationale as the first section of a new `docs/design/frontend.md`
      ([Design docs](#design-docs)) — [09 § 9.4](09-frontend-code-quality.md#94--sidebar-navigation-does-full-page-reloads-spa-routing-only-half-exists)

Tooling that protects every later commit:

- [ ] CI supply-chain gating: `cargo audit`/`cargo deny` + `npm audit` as PR gates; Semgrep on
      PRs; Dependabot/Renovate — [06 § 6.1/6.2](06-dependency-supply-chain.md#61--no-dependency-vulnerability-scanning-runs-in-ci),
      [17 § 17.1](17-cicd.md#171--security-scanning-is-not-a-required-pr-gate)
- [ ] Enforce lint-level style rules through tooling (formatting is already gated): ESLint
      (`typescript-eslint` + `eslint-plugin-svelte`) wired into hooks + CI, and a
      `[workspace.lints]` table in the root `Cargo.toml` — [18 § 18.6](18-documentation-dx.md#186--formatting-is-tooled-and-ci-gated-but-lint-level-style-rules-are-not)

## Stage B — The authorization & multi-tenancy refactor (the spine)

Implements the [authorization design](../docs/design/authorization.md), landed as
**small, individually green PRs** in this order. Resolves
[02 § 2.1/2.2](02-authorization-access-control.md#21--get-apiusers-discloses-every-user-in-the-shared-default-tenant), [10 § 10.3](10-database-data-layer.md#103--email-unique-globally-conflicts-with-the-multi-tenant-model),
[20 § 20.1/20.2](20-business-logic-correctness.md#201--admin-identity-is-inconsistent-across-the-system). Multi-write flows (signup→tenant→membership,
invite acceptance) are wrapped in transactions **as they are written**, not retrofitted —
[10 § 10.2](10-database-data-layer.md#102--multi-operation-flows-are-not-wrapped-in-transactions), [20 § 20.5](20-business-logic-correctness.md#205--partial-failure-consistency-in-multi-step-flows).

The checklist items below are short summaries; their actual spec (schema, claims, enforcement
pattern) is [docs/design/authorization.md](../docs/design/authorization.md). Each item carries
a *design:* link to the section(s) that define it — put those links in the GitHub issue body
(and quote the key details if the assignee works without repo access).

- [ ] Permission catalog: Rust enum of actions with stable string forms —
      design: [RBAC](../docs/design/authorization.md#rbac-db-driven-roles-code-defined-action-catalog)
- [ ] Schema migration: drop `users.tenant_id`; add `tenant_memberships`, `roles`,
      `role_permissions`; seed immutable system roles (owner, admin, member, client) —
      design: [Tenancy & membership](../docs/design/authorization.md#tenancy--membership),
      [RBAC](../docs/design/authorization.md#rbac-db-driven-roles-code-defined-action-catalog)
- [ ] Registration/SSO flow: self-signup creates tenant + owner membership; adapt
      `link_sso_user` to the new schema —
      design: [Tenancy & membership](../docs/design/authorization.md#tenancy--membership)
- [ ] Mailer abstraction (trait + dev console impl + one provider) — prerequisite for
      verification here and invites below — [01 § 1.9](01-authentication-session.md#19--no-password-change-password-reset-or-account-recovery-flow-exists)
- [ ] Email verification on registration + fix SSO auto-linking (account pre-hijacking) —
      [01 § 1.8](01-authentication-session.md#18--no-email-verification-on-registration--account-pre-hijacking-via-sso-auto-linking), [20 § 20.3](20-business-logic-correctness.md#203--sso-account-linking-auto-links-by-email-with-no-verification-step)
- [ ] User lifecycle: `onboarding → active → suspended/archived` transitions (invited users
      start in `onboarding` until first login) — [20 § 20.2](20-business-logic-correctness.md#202--registration-always-assigns-tenant_id--0-and-status--active-bypassing-onboarding);
      design: [Tenancy & membership](../docs/design/authorization.md#tenancy--membership)
- [ ] JWT claims: replace `tenant_id` with `active_tenant_id`; add `POST /api/auth/switch-tenant`
      — design: [Claims & active tenant](../docs/design/authorization.md#claims--active-tenant-the-critical-constraint)
- [ ] Authorization machinery: `TenantContext` + `RequirePermission` extractors, the
      permission-resolution service (request-scoped), 404-on-denied per `conventions.md` §6 —
      design: [Enforcement pattern](../docs/design/authorization.md#enforcement-pattern-declarative-and-hard-to-forget),
      [Three layers](../docs/design/authorization.md#three-layers-keep-them-distinct)
- [ ] Role management endpoints: tenant-admin CRUD for custom roles + assignment; system roles
      immutable; covered by tests (the cost of the DB-driven choice — budget for it) —
      design: [RBAC](../docs/design/authorization.md#rbac-db-driven-roles-code-defined-action-catalog)
- [ ] Invite flow: owner/admin invites an email with a role **and optional entity grants**
      (the client-assignment flow); single-use hashed token; accept creates membership + ACL
      rows in one transaction —
      design: [Invitations](../docs/design/authorization.md#invitations),
      [Resource access resolution](../docs/design/authorization.md#resource-access-resolution-who-sees-what)
- [ ] Entity ACL: `object_access` + `authorize_resource` helper (RBAC-first resolution rule,
      parent inheritance); service-layer ACL cleanup on entity delete + test —
      design: [ReBAC](../docs/design/authorization.md#rebac-entity-level-access),
      [Resource access resolution](../docs/design/authorization.md#resource-access-resolution-who-sees-what),
      [Enforcement pattern](../docs/design/authorization.md#enforcement-pattern-declarative-and-hard-to-forget)
- [ ] Reference feature `projects` + `tasks` in `backend/app/`: full `_api/_db/_service` +
      utoipa + regenerated client + **boundary tests** (owner/admin sees all tenant projects;
      client sees only assigned projects and their tasks; cross-tenant → 404; member without a
      grant on P cannot read P's tasks) — replaces `sample`, which retires
      [07 § 7.4](07-code-structure-architecture.md#74--emptyplaceholder-artifacts) and the `/api/api/sample` path
      [11 § 11.1](11-api-design.md#111--apiapisample--duplicated-path-prefix-ships-in-the-spec-and-client);
      design: the entire [design doc](../docs/design/authorization.md) (this feature
      exercises every layer)
- [ ] Rework `GET /api/users` into a tenant-scoped member listing gated by
      `tenant:manage_members` — closes [02 § 2.1](02-authorization-access-control.md#21--get-apiusers-discloses-every-user-in-the-shared-default-tenant);
      design: [Enforcement pattern](../docs/design/authorization.md#enforcement-pattern-declarative-and-hard-to-forget)
- [ ] Expose the caller's permission set in `UserInfo` so the frontend derives UI capabilities
      — [09 § 9.3](09-frontend-code-quality.md#93--isadmin-is-derived-from-userid--1-which-is-not-the-admin);
      design: [Claims & active tenant](../docs/design/authorization.md#claims--active-tenant-the-critical-constraint)
- [ ] Write `docs/design/authentication.md` capturing the auth design as extended by this
      stage — token lifecycle, cookies, OAuth state, the single-use-token pattern, mailer,
      account lifecycle; content outline in [Design docs](#design-docs), verified starting
      material in [01 § 1.5/1.7](01-authentication-session.md#15--refresh-issues-a-new-token-before-validating-the-token-hash-matches)

## Stage C — Frontend catches up (overlaps the tail of Stage B)

As each backend capability lands, the matching frontend work unblocks.

- [ ] Retire `isAdmin` (`user.id === 1`): capability helpers on `AppState` — `can(permission)`
      derived from the backend permission set; nav visibility and route guards use `can(...)`;
      document the capability model in `docs/design/frontend.md` —
      [09 § 9.3](09-frontend-code-quality.md#93--isadmin-is-derived-from-userid--1-which-is-not-the-admin)
- [ ] Align error codes across backend + frontend: frontend expects `not_authenticated`,
      backend emits `invalid_token`/`expired_token`; settle the canonical `code` set in
      `conventions.md` — [09 § 9.8](09-frontend-code-quality.md#98--frontend-expects-error-code-not_authenticated-backend-never-emits-it), [11 § 11.3](11-api-design.md#113--error-code-strings-dont-match-the-documented-contract),
      [18 § 18.1](18-documentation-dx.md#181--docs-and-code-disagree-in-several-places)
- [ ] Tenant switcher UI for users with multiple memberships —
      design: [Claims & active tenant](../docs/design/authorization.md#claims--active-tenant-the-critical-constraint)
- [ ] Invite UI (owner/admin invites an email + role + project assignment) and an
      invitation-accept page — design: [Invitations](../docs/design/authorization.md#invitations),
      [Resource access resolution](../docs/design/authorization.md#resource-access-resolution-who-sees-what)
- [ ] Projects/tasks page consuming the generated client — the frontend half of the reference
      feature (owner sees all, client sees only assigned) —
      design: [Resource access resolution](../docs/design/authorization.md#resource-access-resolution-who-sees-what)

## Stage D — Hardening & polish (surface is now stable)

Backend resilience & operability:

- [ ] Argon2 hashing via `spawn_blocking` — [19 § 19.1](19-performance-scalability.md#191--argon2-hashing-runs-on-the-async-runtime-without-spawn_blocking)
- [ ] `PRAGMA synchronous = NORMAL` explicit; pool acquire timeout; document the SQLite
      choices + backup strategy in `docs/design/operations.md` —
      [10 § 10.1/10.7](10-database-data-layer.md#101--synchronous-pragma-not-set-durability-under-wal-is-at-sqlite-default)
- [ ] `X-Request-ID` generation/propagation in the trace span — [14 § 14.1](14-logging-observability.md#141--no-request-id--correlation-id-threaded-through-logs)
- [ ] Supervise/log background cleanup-task exits — [13 § 13.4](13-error-handling-resilience.md#134--background-cleanup-tasks-have-no-restartpanic-handling)
- [ ] Container healthcheck; drop obsolete compose `version` key —
      [16 § 16.2/16.3](16-containerization-deployment.md#162--no-healthcheck-in-the-dockerfile--compose)
- [ ] Response compression (`CompressionLayer`) — [19 § 19.6](19-performance-scalability.md#196--asset-serving-cacheetagcompression)
- [ ] Gate `/health?panic=true` to non-prod; consider `/ready` split; document the
      health/readiness semantics in `docs/design/operations.md` —
      [14 § 14.4](14-logging-observability.md#144--public-healthpanictrue-crash-hook-is-available-in-production), [13 § 13.5](13-error-handling-resilience.md#135--health-check-is-liveness-only-no-readiness-distinction)

API contract coherence (code, docs, and client must agree):

- [ ] Pagination: implement the documented cursor shape or relax the convention — applies to
      the new member/project/task list endpoints — [11 § 11.2](11-api-design.md#112--get-apiusers-uses-offset-pagination-and-returns-total-contradicting-conventionsmd),
      [19 § 19.2](19-performance-scalability.md#192--list_users-runs-a-count-on-every-call)
- [ ] `#[serde(deny_unknown_fields)]` on request DTOs (or fix the doc) — [03 § 3.3](03-input-validation-injection.md#33--unknown-fields-in-request-bodies-are-silently-accepted-contradicts-documented-convention)
- [ ] `Retry-After` on 429 — [11 § 11.4](11-api-design.md#114--no-retry-after-header-on-429-despite-documented-convention)
- [ ] Reconcile `conventions.md` with reality; mark unimplemented sections — [18 § 18.1](18-documentation-dx.md#181--docs-and-code-disagree-in-several-places)

Account management (nearly free once the Stage B mailer exists):

- [ ] Change-password (requires current password, revokes other sessions) and
      forgot/reset-password (single-use hashed token) — [01 § 1.9](01-authentication-session.md#19--no-password-change-password-reset-or-account-recovery-flow-exists)
- [ ] Account deletion/anonymization path (uses the `archived` status) — [10 § 10.6](10-database-data-layer.md#106--cascade-deletes-are-configured-anonymizationlifecycle-is-not)
- [ ] Account-lockout DoS trade-off: cap duration or add IP-scoped throttle — [01 § 1.4](01-authentication-session.md#14--account-lockout-enables-trivial-denial-of-service-against-a-known-account)

Frontend standards, UX & accessibility:

- [ ] `About.svelte` raw `fetch` → `api.health.health_check()` — [09 § 9.5](09-frontend-code-quality.md#95--aboutsvelte-calls-the-api-with-raw-fetch-bypassing-the-generated-client)
- [ ] `fetch.ts` `onError`: distinguish offline from server error, snake_case code, dev log —
      [09 § 9.7](09-frontend-code-quality.md#97--fetchts-onerror-middleware-swallows-the-real-error-and-always-returns-500)
- [ ] Type `PageDefinition.component` as `Component` instead of `any` — [09 § 9.6](09-frontend-code-quality.md#96--pagedefinitioncomponent-typed-as-any)
- [ ] Logout confirm is hover-only (keyboard users bypass it); make click-toggled + Escape —
      [09 § 9.9](09-frontend-code-quality.md#99--logout-confirmation-is-mouse-only-and-keyboard-users-bypass-it-entirely)
- [ ] Settings toggles are non-functional placeholders; wire up or mark — [09 § 9.9](09-frontend-code-quality.md#99--logout-confirmation-is-mouse-only-and-keyboard-users-bypass-it-entirely)
- [ ] `auth-refresh-manager`: simplicity & safety pass — fix the stale-timer edge (gate
      `focus`/`storage` rescheduling on `AppState.isLoggedIn`, clear timing keys on auth
      failure, [01 § 1.6](01-authentication-session.md#16--frontend-token-refresh-timing-state-is-stored-in-localstorage)); then simplify where possible without
      losing the tested behaviors ([09 § 9.11](09-frontend-code-quality.md#911--staterunes-usage-is-correct-verified),
      [12 § 12.4](12-testing.md#124--no-frontend-componente2e-tests-only-the-refresh-manager-is-covered) rate it the strongest frontend code — keep it that way);
      record the resulting contract in `docs/design/frontend.md`

## Stage E — Lock it in

Tests (the authorization *boundary* tests already shipped inside Stage B):

- [ ] Role/permission-resolution unit tests, incl. custom roles and system-role immutability —
      [02 § 2.2](02-authorization-access-control.md#22--no-roleauthorization-model-exists-admin-is-not-enforced-anywhere-on-the-backend)
- [ ] Make Google HTTP calls injectable; test the OAuth callback (CSRF mismatch, expired
      state, happy path) — [12 § 12.2](12-testing.md#122--oauth-callback-flow-is-untested-end-to-end)
- [ ] Suspended-user login/refresh rejection tests — [01 § 1.1](01-authentication-session.md#11--suspendedarchived-users-can-still-authenticate-and-refresh)
- [ ] Pre-hijack scenario test (register → SSO link) — [01 § 1.8](01-authentication-session.md#18--no-email-verification-on-registration--account-pre-hijacking-via-sso-auto-linking)
- [ ] Component tests for Login and auth-redirect logic; remove `dummy.test.ts`; optional
      Playwright smoke test (login → protected page → logout) — [12 § 12.4](12-testing.md#124--no-frontend-componente2e-tests-only-the-refresh-manager-is-covered)

Remaining CI/CD:

- [ ] Run `sqlx prepare --check` in CI — [17 § 17.2](17-cicd.md#172--sqlx-prepare---check-is-skipped-in-ci)
- [ ] License allow-list (`cargo deny check licenses`) — [06 § 6.5](06-dependency-supply-chain.md#65--license-compliance-not-tracked)
- [ ] Release workflow: tag → build → push image; rollback procedure documented in
      `docs/design/operations.md` — [17 § 17.3](17-cicd.md#173--no-cd--release-pipeline-versioning-or-rollback-automation)

Backend hygiene (batch into few issues):

- [ ] Service-layer cleanups: drop the HTTP error variant from `auth::Error`; make repo/context
      fields non-`pub`; stop api→repo reach-through — [07 § 7.1/7.2](07-code-structure-architecture.md#71--http-concerns-leak-into-the-domainservice-layer)
- [ ] `map_err` → `#[from]` sweep; comment or remove clippy allows; `#[cfg(test)]` for
      test-only code; avoid the `Row` clone — [08 § 8.1/8.3/8.4/8.5](08-rust-code-quality.md#81--map_err-used-where-from-conversions-are-the-project-standard)
- [ ] Curate startup config logging; stop logging CSRF hashes —
      [04 § 4.1/4.2](04-scrts-sensitive-data.md#41--full-settings-struct-including-db-url-is-logged-at-startup), [14 § 14.3](14-logging-observability.md#143--full-config-dump-at-startup-cross-listed)
- [ ] Pick one `updated_at` mechanism (trigger vs explicit) — [10 § 10.4](10-database-data-layer.md#104--updated_at-trigger-causes-double-writes--recursion-risk-and-returning-may-not-reflect-it)
- [ ] `xtask` overhaul: move the inline `dev`/`release`/`clean`/`dev_init` logic into modules,
      clean up the code, make the styling consistent with the backend, and add small shared
      abstractions (command-running, port-waiting, process supervision helpers) to reduce
      overall size — [07 § 7.3](07-code-structure-architecture.md#73--xtask-is-a-single-388-line-xtaskrs-plus-modules-mixed-responsibilities)
- [ ] Import-style switch (decided): AGENTS.md convention becomes `use module::MyType;`
      (direct type imports); update AGENTS.md and sweep the backend — new code follows the new
      convention from now on — [21 § 21.4](21-general-hygiene.md#214--inconsistent-import-style-vs-the-documented-convention)
- [ ] Write `docs/config.md`: TOML layering/precedence, key reference with defaults, env-only
      environment selection ([Design docs](#design-docs)) —
      [15 § 15.4](15-configuration-environment.md#154--not-all-config-keys-are-documented)
- [ ] README architecture/testing sections; link the design docs from the README —
      [18 § 18.2/18.3](18-documentation-dx.md#182--almost-no-doc-comments-on-public-apis--complex-modules)

Developer experience:

- [ ] Devcontainer: split generic project setup from personal setup (fish/gemini/claude
      configs and volumes become clearly-named opt-in scripts; optional `setup-zsh` variant
      to prove the split) — [18 § 18.7](18-documentation-dx.md#187--devcontainer-bakes-one-developers-personal-setup-into-the-shared-config)
- [ ] Add a `create-feature` agent skill: scaffold a new bounded context from a DB schema
      (migration → `_db`/`_service`/`_api` → authz wiring → utoipa → codegen → frontend →
      tests), using the Stage B projects/tasks feature as the exemplar — **after Stage B
      lands** — [18 § 18.8](18-documentation-dx.md#188--no-guideskill-for-scaffolding-a-new-feature-from-a-db-schema)

Frontend hygiene (batch into one issue):

- [ ] Dead `/user_info.js` proxy; runtime Google Fonts import / unloaded Inter; hardcoded
      `v1.0.0-beta`; global `isLoading` misuse in SecureApi — [09 § 9.10](09-frontend-code-quality.md#910--small-issues-dead-proxy-entry-unloaded-font-hardcoded-version-global-loading-flag-silent-bootstrap-failure)
- [ ] `console.*` calls in production code — [21 § 21.1](21-general-hygiene.md#211--consolelogconsoleerror-left-in-frontend-production-code)
- [ ] Commented-out code, dead `AppState.userId`, package name drift —
      [21 § 21.2/21.3/21.5](21-general-hygiene.md#212--commented-out-code-blocks)

## Deferred (document, revisit when needed)

- JWT key rotation (`kid` + multiple decode keys) — [04 § 4.3](04-scrts-sensitive-data.md#43--jwt-secret-file-good-handling-document-rotation)
- Access-token deny-list for instant logout — [01 § 1.2](01-authentication-session.md#12--logout-does-not-revoke-the-access-token-only-the-refresh-token)
- Application metrics (`/metrics`, RED) — [14 § 14.2](14-logging-observability.md#142--no-application-metrics-exposed)
- Idempotency keys for mutating endpoints — [11 § 11.5](11-api-design.md#115--no-idempotency-support-for-mutating-endpoints)
- SQLite write-throughput ceiling / Postgres path — [19 § 19.4](19-performance-scalability.md#194--would-it-handle-10-traffic--sqlite-write-serialization-is-the-ceiling)
- Permission-resolution TTL cache with invalidation (only if measured)
- Lazy-load page components / bundle splitting — [19 § 19.5](19-performance-scalability.md#195--frontend-bundle-no-code-splittinglazy-loading-small-app-so-low-impact)
- Extract `auth-refresh-manager` as a standalone npm package (after the Stage D
  simplicity/safety pass proves the API surface is stable)

---

## Why this order (and not the others)

- **Authz last** (all polish first): you'd polish `list_users`, `sample`, `UserInfo`, and
  registration — all rewritten by Stage B — and carry the tenant-0 disclosure the whole time.
- **Authz literally first** (before Stage A): the biggest change on top of a base that still
  drops SIGTERM requests, has no body limits, and no CI security gate. Stage A is a day or two
  of cheap insurance that makes the refactor safer to land.

**The one dependency to watch:** the only frontend items that must wait for backend Stage B
are the `isAdmin`→permissions change and the error-code alignment. Everything else in Stages
A/C/D frontend work is independent and can proceed in parallel.
