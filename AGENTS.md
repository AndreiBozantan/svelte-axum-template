# SVELAXUM - Fullstack Webapp Template

Rust + Svelte fullstack template. Backend: Axum + SQLite + sqlx. Frontend: Svelte 5 (runes) + Vite.

# WORKSPACE
- Cargo.toml: workspace root with members [platform, api]
- platform/: library crate with identity and shared code
- app/: binary crate (app.rs), will add additional APIs in the future
- frontend/: Svelte 5 SPA with Vite
- migrations/: SQL migration files embedded via sqlx; main SQL schema is in migrations/01_initial_schema.sql
- data/: config files and SQLite database

# RUN COMMANDS
- cargo check - check for backend errors
- cargo test - run tests
- npm run dev       (concurrent backend + frontend with hot reload)
- cd frontend && npm run dev  (frontend standalone)

# ADDITIONAL INFO
The module tree is intentionally declared in a single file for each crate, platfrom/platfrom.rs and app/app.rs.

The project is organized to use a DDD pattern for organizing files and folders.
Each bounded context has a folder with sub features, e.g. the platform/identity has as sub features: auth, oauth, tokens, users.
Each subfeature has 3 main files: subfeature_api.rs, subfeature_db.rs, subfeature_service.rs and optionally subfeature_tests.rs and subfeature_utils.rs.
You can use the platform/identity/users/ as a model for when implementing new features.

# CODING STYLE
- imports: `use module;` and then qualify types with `module::MyType` in the code; avoid `use module::MyType`.
- make sure to use latest idiomatic Rust and work like an world-expert Rust senior software engineer.
- try to avoid map_err and use error conversions instead.
- try to use chaining of method calls when possible, in a functional programming style.
