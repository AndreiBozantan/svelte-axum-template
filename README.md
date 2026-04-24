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

# Embedded Assets & Updates
The frontend static files are embedded directly into the Rust binary at **compile time** using the `rust-embed` crate.

### How to update embedded files
Whenever you make changes to the frontend code and want them to be reflected in the backend server (the one running on port `3000`), you must:
1.  **Build the frontend**: `cd frontend && npm run build`
2.  **Recompile/Restart the backend**: `cargo run` (or `cargo build`)

### Debug vs Release Mode
- **Embedding works in both modes**: Whether you use `cargo run` (debug) or `cargo build --release`, the files currently sitting in `frontend/dist` will be baked into the resulting executable.
- **Development Workflow**: During active development (`npm run dev`), you typically don't need to worry about embedding. The Vite dev server (port `5173`) serves the frontend with hot-reloading and proxies API requests to the backend. You only need to build/embed when preparing for a production-like test or final deployment.

# Backend - Rust Axum
- located in `./backend`
- serves front end assets that are embedded in the binary during the build
- middleware for checking authorization header
- /api route example using authorization header
- /secure route example using JWT for authorization

Run `cargo run` from inside the repo root folder to start the backend server independently from the frontend.

## Backend Configuration
The backend can be configured using TOML files in the project root directory:
- `configs.default.toml` - Default configuration
- `configs.development.toml` - Development-specific overrides
- `configs.production.toml` - Production configuration example
- `configs.local.toml` - Local overrides (git-ignored)


## Database Migration Control
You can run the database migrations by using the `migrate` command provided by the backend.
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
- Located in `./frontend`.
- Includes a navbar with login and logout.
- Secure page that shows session information once logged in.
- API fetch example, login is required.

Run `npm run dev` from inside the `./frontend` directory to start serving the frontend.


# OAuth2 SSO Setup (Google)

This template includes Google OAuth2 SSO integration. To set it up:

## 1. Create Google OAuth2 Credentials

1.  **Google Cloud Console**: Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  **Create Project**: Click the project dropdown in the top bar and select "New Project". Give it a name and click "Create".
3.  **Configure Google Auth Platform** (formerly OAuth consent screen):
    *   Navigate to **APIs & Services > Google Auth platform**.
    *   **Branding**: Click **Get Started** or the **Branding** tab. Fill in the required App Information (App name, user support email, developer contact info) and click **Save and Continue**.
    *   **Audience**: Go to the **Audience** tab (or step). Select **External** as the User Type. If you are using a personal `@gmail.com` account, this may be selected by default as "Internal" is restricted to Workspace users.
    *   **Scopes**: You can skip or add `openid`, `https://www.googleapis.com/auth/userinfo.email`, and `https://www.googleapis.com/auth/userinfo.profile`.
4.  **Create Credentials**:
    *   Navigate to the **Clients** tab (or **APIs & Services > Credentials**).
    *   Click **+ Create Credentials** at the top and select **OAuth client ID**.
    *   Select **Web application** as the Application type.
    *   **Authorized JavaScript origins**: Add `http://localhost:5173` (for the Svelte dev server).
    *   **Authorized redirect URIs**: Add `http://localhost:3000/api/auth/oauth/google/callback`.
    *   Click **Create**.
5.  **Get Your Keys**: A dialog will appear showing your **Client ID** and **Client Secret**. Copy these for the next step.

## 2. Configure the Backend

⚠️ **IMPORTANT SECURITY NOTE**: Never commit OAuth secrets to git!

1.  Create a file named `configs.local.toml` in the **project root directory** (this file is already in `.gitignore`).
2.  Copy the `[oauth]` section from `configs.default.toml` into your `configs.local.toml`.
3.  Paste your credentials:

```toml
[oauth]
google_client_id = "your-client-id-here"
google_client_secret = "your-client-secret-here"
```

Alternatively, you can use environment variables: `APP_OAUTH_GOOGLE_CLIENT_ID` and `APP_OAUTH_GOOGLE_CLIENT_SECRET`.

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