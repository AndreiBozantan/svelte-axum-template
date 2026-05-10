# API Codegen Plan

## Goal

Automatically generate frontend TypeScript API types and client helpers from backend endpoint definitions so new backend endpoints do not require manually written frontend API code.

## Current state

- Frontend currently uses a manual client in `frontend/src/lib/api.ts`.
- Frontend request/response types are curated manually in `frontend/src/lib/types.ts`.
- Backend routes are defined manually in `backend/src/app/router.rs` and handlers in `backend/src/routes/*.rs`.
- There is no existing OpenAPI/Swagger or Rust-to-TypeScript codegen integration.

## Recommended solution

Use OpenAPI generation on the Rust backend, then generate frontend TypeScript types and optional client wrappers from the spec.

### Backend

1. Add Rust crates for OpenAPI generation:
   - `utoipa`
   - `utoipa-axum`

2. Annotate shared request/response payload types with `#[derive(utoipa::ToSchema)]`.

3. Annotate route handlers and router configuration so an OpenAPI spec can be generated.

4. Expose the generated OpenAPI document as either:
   - a build artifact such as `openapi.json`, or
   - a runtime route such as `/openapi.json`.

### Frontend

1. Add a codegen tool to the frontend:
   - `openapi-typescript`, or
   - `openapi-typescript-codegen`.

2. Add an npm script like `generate:api`.

3. Generate type definitions and optionally generated API client helpers into `frontend/src/lib/generated/`.

4. Replace manual types and client code in `frontend/src/lib/api.ts` and `frontend/src/lib/types.ts` with generated code, while keeping higher-level auth/session logic in place.

## Implementation steps

1. Add OpenAPI crates to `backend/Cargo.toml` and configure them.
2. Define shared backend DTOs for request and response payloads.
3. Derive OpenAPI schemas on those types.
4. Update backend route registration to expose the OpenAPI spec.
5. Add frontend codegen packages and a generation script.
6. Generate frontend artifacts from the spec and commit generated files.
7. Update the frontend to import generated types and client functions.

## Validation

When a new backend endpoint is added:

1. Generate the OpenAPI spec.
2. Run the frontend generation script.
3. Confirm generated TS types include the new endpoint.
4. Confirm the frontend compiles without manually editing API client types.

## Alternatives

- If only type synchronization is needed, use Rust-to-TypeScript serializers instead of full OpenAPI.
  - Examples: `ts-rs`, `serde_ts`, or `type-saurus`.
- If you want a stricter contract, maintain the API spec in Rust and derive frontend types from it.

## Notes

- `logout` and other state-changing operations should remain `POST` endpoints.
- This plan is best for a backend-driven API contract, where Rust types are the source of truth.
- Generated code still requires regeneration whenever backend request/response schemas change.
