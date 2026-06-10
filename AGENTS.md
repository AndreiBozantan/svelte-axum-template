# SVELAXUM - Fullstack Webapp Template

Rust + Svelte fullstack template. Backend: Axum + SQLite + sqlx. Frontend: Svelte 5 (runes) + Vite.

# BACKEND STRUCTURE
- Cargo.toml - workspace root with members [platform, api]
- platform/ - backend library crate with platform code and identity APIs
- platform/identity/ - auth, oauth, tokens and users related APIs
- app/ - backend binary crate (app.rs) with application specific APIs 
- frontend/ - Svelte 5 SPA with Vite
- migrations/ - SQL migration files embedded via sqlx; main SQL schema is in migrations/01_initial_schema.sql
- data/ - config files and SQLite database

# BACKEND DESIGN
- the module tree is intentionally declared in a single (non-idomatic) file for each crate, platfrom/platfrom.rs and app/app.rs
- the project is organized to use a DDD pattern for organizing files and folders
- each bounded context has a folder with sub features, e.g. the platform/identity has as sub features: auth, oauth, tokens, users
- each subfeature has 3 main files: subfeature_api.rs, subfeature_db.rs, subfeature_service.rs and optionally subfeature_tests.rs and subfeature_utils.rs.
- you can use the platform/identity/users/ as a model for when implementing new features

# BACKEND CODING STYLE
- imports: `use module;` and then qualify types with `module::MyType` in the code; avoid `use module::MyType`.
- avoid map_err and use error conversions instead
- use chaining of method calls when possible, in a functional programming style
- use validator::Validate to validate the inputs
- use idiomatic Rust and work like an world-expert Rust senior software engineer
