# API Codegen

The TypeScript API types and client are generated from the Rust backend, so adding an endpoint requires zero hand-written frontend API code. The conventions the generated API encodes are in `conventions.md`.

## How it works

- Backend handlers and DTOs are annotated with `utoipa` / `utoipa-axum`, producing an OpenAPI 3.1 spec (`openapi.json` at the repo root, committed).
- `frontend/scripts/generate-api.ts` reads the spec and generates, under `frontend/src/lib/generated/` (committed, never hand-edited):
  - `api.d.ts` — types for every endpoint, via `openapi-typescript`
  - `endpoints.ts` — a method-based client grouped by tag (e.g. `api.auth.login(body)`), wrapping the `openapi-fetch` runtime client
- The hand-written part is `frontend/src/lib/fetch.ts` (auth middleware: 401 → coalesced silent refresh → retry) and `frontend/src/lib/api.ts`.

## Adding an endpoint

1. Add the Rust handler + DTOs, annotated with `#[utoipa::path(...)]` and `ToSchema`.
2. Run `cargo xtask make openapi` — regenerates `openapi.json` and the frontend client.
3. Commit the regenerated files together with the code change.
4. Call it from the frontend via the generated client: `api.<tag>.<operation>(...)`.

## Drift checks

`xtask/checks.rs` verifies that `openapi.json` matches the backend code and that `frontend/src/lib/generated/` matches the spec. These run in pre-commit/pre-push hooks and CI, so forgetting step 2 fails the build with a message telling you to run `cargo xtask make openapi`.

## Gotchas

- Handlers must return typed `Json<T>`, never `serde_json::Value` — the schema describes what handlers *claim* to return.
- Newtype IDs need `#[schema(value_type = i64)]` to emit the primitive instead of a named schema.
- Rust `Option<T>` becomes `T | null` in OpenAPI 3.1, not an absent field — frontend checks must use `!== null`, not truthiness.
- Swagger UI is feature-gated: `cargo run --package app --features swagger`, then browse `http://localhost:3000/docs`.
