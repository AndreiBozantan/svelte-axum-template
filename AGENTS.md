# SVELAXUM - Fullstack Webapp Template

Rust + Svelte fullstack template. Backend: Axum + SQLite + sqlx. Frontend: Svelte 5 (runes) + Vite.

# REPO STRUCTURE
- Cargo.toml - workspace root with member [backend]
- frontend/ - Svelte 5 SPA with Vite
- backend/ - unified backend package containing platform and application code
- data/ - config files and SQLite database
- migrations/ - SQL migration files embedded via sqlx; main SQL schema is in migrations/01_initial_schema.sql

# BACKEND STRUCTURE
- backend/platform/ - platform library code (identity, shared, internal)
- backend/platform/identity - APIs and services for: users, tokens, auth, oauth
- backend/app/ - application specific API endpoints and corresponding services
- backend/test/ - unit and integration tests (without the 's' suffix to prevent separate integration test binary builds, reducing binary count to exactly 1)

# BACKEND DESIGN
- the module tree is declared in a single (non-idiomatic) file at backend/main.rs to avoid polluting file tree with mod.rs files 
- the project is organized to use a DDD pattern for organizing platform and app features
- each bounded context (e.g. backend/platform/identity) has sub-features: auth, oauth, tokens, users
- each subfeature has 3 main files: subfeature_api.rs, subfeature_db.rs, subfeature_service.rs and optionally subfeature_tests.rs and subfeature_utils.rs.
- backend/platform/identity/users/ - can be used as a template when implementing new features

# BACKEND CODING STYLE
- imports: `use module;` and then qualify types with `module::MyType` in the code; avoid `use module::MyType`.
- avoid map_err and use error conversions instead
- use chaining of method calls when possible, in a functional programming style
- use validator::Validate to validate the inputs
- use idiomatic Rust and work like an world-expert Rust senior software engineer

