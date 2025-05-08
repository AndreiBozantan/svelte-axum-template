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


# Building the project
- Install the following:
    - NodeJs - [Install](https://nodejs.org/en/download/)
    - Rust  - [Install](https://www.rust-lang.org/tools/install)

- Change current directory in the project folder:
    - `cd <your-project-name>` - to go to the project folder

- Build the frontend code:
    - `cd front_end`
    - `npm install` - to download all module dependencies inside root directory of project
    - `npm run build` - to bundle the js/svelte code into public folder

- Initialize the database for sqlx compile time checks, before building the backend:
    - `cd ..` - to go back to the root directory of the project
    - `cargo sqlx database create --database-url sqlite:db.sqlite` - to create the database
    - `cargo sqlx migrate run --database-url sqlite:db.sqlite --source migrations` - to run the migrations
    - `cargo sqlx --workspace prepare --database-url sqlite:db.sqlite` - to create metadata for compile time checks

- Build the backend code and run the server:
    - `cargo build` - to build the backend code
    - `cargo run` - to start the the server

- Access in browser at `http://localhost:8080/`

In case you need to build both at once and use Linux, run `./build-fullstack.sh`


# Back end - Rust Axum
- located in `./back_end`
- serves front end directory
- middleware for checking authorization header
- middleware for checking session that user exists
- store example that holds token secret for authorization
- /api route example using authorization header
- /secure route example using sessions for authorization

run as `cargo run` from parent directory and not needed to run inside `./back_end` folder

# Front end - Svelte
- Located in `./front_end`
- navbar with login and logout
- secure page that shows session information once logged in
- api fetch example, log in not required

run as `npm run build` from inside the `./front_end` directory to build the static serve file directory.

# Version History
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

## Version 0.4.2
- migration of `axum-sessions` to `tower-sessions` see [pr#14](https://github.com/jbertovic/svelte-axum-project/pull/14)
- removal of secret key warning due to migration

## Version 0.4.1
- bumped version on backend; `axum` to 0.6.20, `axum-sessions` to 0.5, `tower-http` to 0.4
- bumped versions on front-end; `vite-plugin-svelte` to 2.4.2, `svelte` to 4.0.5, `vite` to 4.4.5
- backend changed how servedir works from `tower-http` for serving front end static assets

## Version 0.4.0
  - updated to `axum` 0.6
  - changes to State usage; how its setup with route and called from middleware
  - changes to ordering of parameters in functions; last parameter can consume request body
  - eliminated `axum::extract::RequestParts` with help from update on `axum-sessions`
- updated to `axum-sessions` 0.4 to match
- incremented `tokio` version to 1.24
- old `axum` 0.5 version is kept under branch `v0.3_Axum0.5`
