# API Conventions

The contract every backend endpoint follows. Frontend code (and any future service consuming this API) can rely on these rules without reading per-endpoint documentation.

These conventions exist *before* the codegen plan because the generated TypeScript client and Rust handlers will both encode them. Changing them later means regenerating + rewriting consumers.

---

## 1. HTTP status code carries the success/failure signal

Status code is the primary signal. The response body holds the *content* — success data or error details — but is not consulted to determine "did this work."

| Status | Meaning |
|--------|---------|
| `200 OK` | Request succeeded, response body contains the resource or operation result. |
| `201 Created` | Resource created. `Location` header points to it where applicable. |
| `204 No Content` | Operation succeeded, no body. Use for logout, revoke, delete. |
| `400 Bad Request` | Request was malformed or failed validation (wrong types, missing fields). |
| `401 Unauthorized` | No valid authentication. Client should refresh or redirect to login. |
| `403 Forbidden` | Authenticated but not allowed. Do not retry without changing identity. |
| `404 Not Found` | Resource does not exist (or the caller can't see it — see §6). |
| `409 Conflict` | State conflict (e.g., email already registered). |
| `422 Unprocessable Entity` | Semantic validation failure (input parsed, but business rule rejected it). |
| `429 Too Many Requests` | Rate limited. `Retry-After` header set. |
| `500 Internal Server Error` | Unexpected server error. Client should not retry without backoff. |
| `503 Service Unavailable` | Temporary, retry with backoff. |

**No `{"result": "ok"|"error"}` envelope.** The status code is the result.

---

## 2. Success responses

The body is the resource or the operation output, directly:

```json
// GET /api/users/me  →  200 OK
{ "id": 42, "email": "alice@example.com", "tenant_id": 1 }
```

```json
// POST /api/auth/login  →  200 OK
{ "user": { "id": 42, "email": "alice@example.com", "tenant_id": 1 } }
```

```json
// POST /api/auth/logout  →  204 No Content
// (no body)
```

Wrap a list in an object so it's extensible (pagination, totals) without a breaking change:

```json
// GET /api/users  →  200 OK
{ "items": [ ... ], "next_cursor": "..." }
```

Never return a top-level array. Once shipped, you cannot add `total` / `next_cursor` without breaking clients.

---

## 3. Error responses

Every 4xx/5xx response uses the same shape (RFC 7807 Problem Details, simplified):

```json
{
  "code": "invalid_credentials",
  "message": "Email or password is incorrect.",
  "details": { /* optional, structured */ }
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `code` | Yes | Stable, machine-readable identifier in `snake_case`. Clients branch on this. Never localize. |
| `message` | Yes | Human-readable, may be shown to the user. May be localized in the future. |
| `details` | No | Structured per-code data. For `validation_failed`, an array of `{ field, code }` entries. |

**`code` values are part of the API contract.** Adding new ones is non-breaking; renaming/removing them is breaking. Define them in one place (`backend/platform/shared/api.rs`) and reuse.

Standard codes the template uses:

- `invalid_credentials` — login failed
- `not_authenticated` — no/invalid access token
- `token_expired` — refresh required
- `forbidden` — authenticated but not allowed
- `not_found` — resource missing
- `validation_failed` — input failed validation; `details` lists fields
- `conflict` — state conflict (e.g., email already registered)
- `rate_limited` — slow down; `Retry-After` set
- `internal_error` — unexpected server error; safe message only

Server logs may contain more detail; the response body never leaks internals (stack traces, library error strings, SQL).

---

## 4. Methods and resource shape

Standard REST. No "verb in the URL" except for clearly non-CRUD actions.

| Method | Use for | Idempotent? |
|--------|---------|-------------|
| `GET` | Read | Yes |
| `POST` | Create, or non-idempotent action | No |
| `PUT` | Replace entire resource | Yes |
| `PATCH` | Partial update | No (treat as no) |
| `DELETE` | Remove | Yes |

State-changing operations are **never `GET`**, even when convenient. `/api/auth/logout` is `POST`. `/api/auth/refresh` is `POST`. The OAuth callback is `GET` only because the OAuth spec requires it.

URLs are plural nouns for collections, IDs for items:

```
GET    /api/users              → list
POST   /api/users              → create
GET    /api/users/{id}         → read one
PATCH  /api/users/{id}         → partial update
DELETE /api/users/{id}         → delete
POST   /api/users/{id}/suspend → non-CRUD action
```

Auth endpoints are an exception (they're operations, not resources):

```
POST /api/auth/login
POST /api/auth/logout
POST /api/auth/refresh
GET  /api/auth/oauth/google
GET  /api/auth/oauth/google/callback
```

---

## 5. Authentication

- Access token: HttpOnly cookie (`access_token`), 16 minutes default. Short-lived.
- Refresh token: HttpOnly cookie (`refresh_token`), scoped to `/api/auth/refresh`. Long-lived; rotated on every refresh.
- Programmatic clients (CLI, server-to-server) may use `Authorization: Bearer <token>` instead of cookies. The backend already supports both (`backend/platform/shared/cookies.rs`).

Endpoints requiring auth return `401` with `code: "not_authenticated"` or `code: "token_expired"` when the token is missing/invalid. Clients use the code to decide between "redirect to login" and "attempt silent refresh."

---

## 6. Information disclosure

When a resource exists but the caller is not allowed to see it, return `404`, not `403`. `403` confirms the resource exists, which is itself information.

When an authentication step fails (wrong email *or* wrong password), return one error: `invalid_credentials`. Never distinguish "no such user" from "wrong password" in the response.

When validation fails on multiple fields, return all of them in `details`, not just the first one. Saves a round trip and matches what UIs need.

---

## 7. Versioning

The API is unversioned today (`/api/...`). When the first breaking change is needed:

- Prefer additive changes (new fields, new endpoints, new error codes) — these are non-breaking and don't need a version bump.
- For genuine breaks, version via URL prefix: `/api/v2/...`. Old version stays operational for a deprecation window.
- The OpenAPI spec carries `info.version` matching the Cargo crate version. CI fails if the spec drifts from the code (see `codegen.md`).

Adding a field to a response: non-breaking. Removing or renaming a field: breaking. Tightening validation: breaking. Loosening validation: non-breaking. Changing an error `code` string: breaking.

---

## 8. Pagination, filtering, sorting

For list endpoints:

```
GET /api/users?cursor=abc&limit=50&sort=-created_at&filter[status]=active
```

- **Cursor pagination** by default (opaque `cursor` string, `next_cursor` in the response). Offset pagination breaks under writes; don't use it.
- `limit` is an integer; the server caps it (e.g., max 100) and returns the actual count.
- Sort keys prefixed with `-` for descending: `sort=-created_at`.
- Filter keys nested under `filter[...]` to avoid collisions with control parameters.

Don't add these until needed — but when you do, follow this shape so clients can be generic.

---

## 9. Request bodies

- `Content-Type: application/json`. No form-encoded bodies on JSON APIs.
- Field names in `snake_case` to match the Rust serialization defaults. The OpenAPI codegen produces TS types preserving this; the frontend uses `snake_case` for API DTOs (and may convert to `camelCase` only at the UI boundary if desired).
- Unknown fields in a request body are **rejected** (`400 validation_failed`). This catches client typos. (`serde(deny_unknown_fields)` on request DTOs.)
- Unknown fields in a response are **ignored** by clients. Lets the server add fields without breaking older clients.

---

## 10. Idempotency for unsafe operations

For POSTs that create resources or have side effects, accept an `Idempotency-Key` header. The server stores `(key, response)` for 24h and returns the cached response on retry with the same key.

Not implemented today. Add when needed; design the storage in mind so it doesn't become a retrofit.

---

## 11. CORS

The backend serves the SPA from the same origin in production (assets embedded via `rust-embed`). No CORS needed.

In development, the Vite dev server proxies `/api/*` to the backend, so requests are still same-origin from the browser's perspective. No CORS needed.

If a future architecture splits the frontend onto a separate domain (CDN, separate deploy), CORS will need explicit configuration — at that point, add a `server.cors_allowed_origins` setting. Until then, do not enable CORS.

---

## 12. Observability

Target convention (request-ID propagation is not implemented yet):

- `X-Request-ID` — propagated from the incoming request, generated if absent. Logs include the same ID.
- Server logs include status code, path, method, latency, request ID, and structured key-value fields for auth events.

Clients should log the `X-Request-ID` on errors so support can correlate.

---

## Open questions / deferred decisions

These are *not* part of v1 but should be revisited:

- **Localization of `message`.** Currently English. If product needs multi-locale errors, add an `Accept-Language` header convention and translate `message` server-side; `code` stays untranslated.
- **Soft deletes vs hard deletes.** Pick one per resource and document it. Don't mix.
- **Bulk operations.** Need an `Idempotency-Key` story (§10) before adding bulk POST endpoints.
