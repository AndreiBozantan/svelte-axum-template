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

In dev mode, the vite config is set to proxy the backend API requests to the backend server, so you can access the API at `http://localhost:5173/`.


# Build the release version
Execute `npm run build` in the project root folder, to build the frontend and backend in release mode. The npm script will build the frontend **before** the backend, as the frontend static files are embedded in the backend binary.

Optionally, you can execute `npm run clean` before the build, to remove all previous build artifacts, including the `node_modules` folders, so that the build starts from a clean state.
After running the clean command, you have to run `npm run dev:init` once, to reinitialize the project before running in dev mode.


# Backend - Rust Axum
- located in `./backend`
- serves front end assets that are embedded in the binary during the build
- middleware for checking authorization header
- /api route example using authorization header
- /secure route example using JWT for authorization

Run `cargo run` from inside the repo root folder to start the backend server independently from the frontend.

## Backend Configuration
The backend can be configured using TOML files in the `./config` directory:
- `default.toml` - Default configuration
- `development.toml` - Development-specific overrides
- `production.toml` - Production configuration example

### Database Migration Control
You can run the database migrations by using the `migrate` command in the backend.
It will run all pending migrations from the `migrations` directory, or the embedded migrations if the directory does not exist.

```bash
./your-app migrate run # run this in production
```
or
```bash
cargo sqlx migrate run # run this in development
```
When deploying to production, do not copy the migrations directory to the production server. You should use the embedded migrations instead, which are included in the binary.

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

# OAuth2 SSO Setup (Google)

This template includes Google OAuth2 SSO integration. To set it up:

## 1. Create Google OAuth2 Credentials

1. Go to the [Google Cloud Console](https://console.developers.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API (for user info)
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Choose "Web application"
6. Set the authorized redirect URI to: `http://localhost:3000/auth/oauth/google/callback`

## 2. Configure the Backend

⚠️ **IMPORTANT SECURITY NOTE**: Never commit OAuth secrets to git!

Create `local.toml` (git-ignored) based on `default.toml` in the `./backend/config` directory and add your Google OAuth credentials.

## 3. Using OAuth2 Login

1. Start the application with `npm run dev`
2. Navigate to the login page
3. Click "Sign in with Google"
4. Complete the Google OAuth flow
5. You'll be redirected back and automatically logged in

OAuth2 users are stored in the same `users` table with:
- `sso_provider`: "google"
- `sso_id`: Google user ID
- `password_hash`: NULL (since OAuth users don't have passwords)

The OAuth flow generates the same JWT tokens as regular login, so all existing authentication middleware works seamlessly.