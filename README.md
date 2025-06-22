# svelte-axum-template

Starting project template for Rust, Axum, Sqlite backend and Svelte frontend.  Simple Single-Page-App (SPA) example.  Does not use SvelteKit.

Work in progress (new features coming), but should be usable as a starting point.

# Cloning the template
## Using Cargo
- Must have cargo generate installed: `cargo install cargo-generate`
- Then use `cargo generate AndreiBozantan/svelte-axum-project -n <your-project-name>`

## Using git template
- you can also just hit the "use this template" button in green on top of the repo
- if you have gh cli installed check out `--template` option


# Running the project
- Install the following:
    - NodeJs - [Install](https://nodejs.org/en/download/)
    - Rust  - [Install](https://www.rust-lang.org/tools/install)

- Change current directory in the project folder:
    - `cd <your-project-name>` - to go to the project root folder.

- Initialization - run once before starting in dev mode:
    - `npm run dev:init`

- Run the project in dev mode, with hot reloading:
    - `npm run dev`

By default, the backend will be available at `http://localhost:3000` and the frontend at `http://localhost:5173`.

In dev mode, the vite config is set to proxy the backend requests to the backend server.


# Build the release version
Execute `npm run build` in the project root folder, to build the frontend and backend in release mode. The npm script will build the frontend before the backend, as the static files are embedded in the backend binary.

Optionally, you can execute `npm run clean` before the build, to remove all previous build artifacts, including the node_modules folders, so that the build starts from a clean state.
After running the clean command, you have to run `npm run dev:init` once, to reinitialize the project before running in dev mode.


# Backend - Rust Axum
- located in `./backend`
- serves front end directory
- middleware for checking authorization header
- middleware for checking session that user exists
- store example that holds token secret for authorization
- /api route example using authorization header
- /secure route example using sessions for authorization

Run `cargo run` from inside the `./backend` folder to start the backend server.

## Backend Configuration
The backend can be configured using TOML files in the `./backend/config` directory:
- `default.toml` - Default configuration
- `development.toml` - Development-specific overrides
- `production.toml` - Production configuration example

### Database Migration Control
By default, the application automatically runs database migrations on startup. This can be controlled via the `run_db_migrations_on_startup ` setting:

```toml
[database]
url = "sqlite:db.sqlite"
max_connections = 5
run_db_migrations_on_startup  = true  # Set to false to disable automatic migrations
```

**For Development**: Keep `run_db_migrations_on_startup  = true` for convenience.

**For Production**: Set `run_db_migrations_on_startup  = false` and run migrations manually:
```bash
./your-app migrate run
```

This provides better control over database schema changes in production environments.

# Frontend - Svelte
- Located in `./frontend`
- navbar with login and logout
- secure page that shows session information once logged in
- api fetch example, log in not required

Run `npm run dev` from inside the `./frontend` directory to start serving the frontend.


# Version History

## Version 0.7.2
- update frontend to use Svelte 5
- use npm scripts for the build process
- add support for running the app in dev mode, with hot reloading

## Version 0.7.1
- load config from toml files and env variables, see [pr#6](https://github.com/AndreiBozantan/svelte-axum-template/pull/6)
- some cleanup of the backend code

## Version 0.7
- update to use Rust edition 2024, see [pr#3](https://github.com/AndreiBozantan/svelte-axum-template/pull/3)

## Version 0.6
- add sqlite database example with `sqlx`, see [pr#2](https://github.com/AndreiBozantan/svelte-axum-template/pull/2)

## Version 0.5
- embedding static files into the binary using `cargo-embed-file` see [pr#1](https://github.com/AndreiBozantan/svelte-axum-template/pull/1)
- updated to `axum` 0.8.4