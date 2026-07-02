# 16 — Containerization & Deployment

This is a highlight. Multi-stage build with dependency caching, `scratch` runtime, non-root,
pinned base images by digest, and a hardened compose file. Findings are refinements.

---

## 16.1 — `configs.production.toml` selection depends on env var, but the image sets none

- **Severity:** Important (ties to 15.1)
- **Location:** `Dockerfile:75-98` (no `ENV APP__SERVER__ENV=production`), `docker-compose.yml`
  (no environment block setting it).
- **Finding:** Because the committed `configs.common.toml` sets `env = "development"` (see
  [15](15-configuration-environment.md) 15.1) and the container sets no `APP__SERVER__ENV`, the
  containerized app resolves its environment to `development`. The `data/` config files aren't
  even copied into the `scratch` image (only the binary, certs, and an empty `/data` volume are),
  so at runtime the app falls back to defaults + env vars — and with no env var, the effective
  env is whatever the compiled-in default plus any mounted config says. The net effect is
  ambiguous and depends on what lands in the `/data` volume.
- **Risk:** The production container may not actually run in production mode. Deployment behavior
  depends on volume contents rather than being explicit.
- **Recommendation:** Set `ENV APP__SERVER__ENV=production` in the Dockerfile (or in compose), and
  fix 15.1 so environment selection is unambiguous. Document how config reaches the `/data` volume
  in production.

---

## 16.2 — No `HEALTHCHECK` in the Dockerfile / compose

- **Severity:** Minor
- **Location:** `Dockerfile` (no `HEALTHCHECK`), `docker-compose.yml` (no `healthcheck:`).
- **Finding:** A `/health` endpoint exists but nothing wires it to a container healthcheck, so
  orchestrators can't tell if the app is actually serving. The `scratch` image has no shell/curl,
  so a healthcheck would need the binary itself to support a health subcommand or an exec probe.
- **Recommendation:** Add a compose `healthcheck` (or Kubernetes probe) hitting `/health`. Since
  `scratch` lacks curl, either add a tiny `app healthcheck` subcommand or use the orchestrator's
  HTTP probe rather than a container-internal one.

---

## 16.3 — `docker-compose.yml` uses obsolete `version` key and is otherwise dev-oriented

- **Severity:** Minor
- **Location:** `docker-compose.yml:1` (`version: "3.8"`), ports bound to `127.0.0.1:8080`.
- **Finding:** The `version` top-level key is obsolete in Compose v2 (ignored/ warned). The file
  is correctly hardened (`read_only`, `cap_drop: ALL`, `no-new-privileges`, tmpfs) and binds to
  localhost — clearly intended for local use, which is good and matches the review's concern about
  not accidentally being production. Just note there's no TLS here, consistent with the "put a
  proxy in front" assumption (see [05](05-http-transport-security.md)).
- **Recommendation:** Drop the `version` key. Keep the hardening. Document that this compose is
  local-only and prod needs a TLS-terminating proxy + explicit env.

---

## 16.4 — Build reproducibility and caching are strong; verified

- **Severity:** Informational
- **Location:** `Dockerfile:20-72`, `.dockerignore`.
- **Finding:** Base images are pinned by digest, dependencies are built in a separate cached layer
  before source is copied, `SQLX_OFFLINE=true` builds against committed `.sqlx/`, and
  `.dockerignore` uses an allow-list (`**` then `!` includes) so build context is minimal. `npm ci`
  (not `install`) is used. This is a clean, reproducible, well-ordered build. No change needed.

---

## 16.5 — Runtime image hardening is excellent; verified

- **Severity:** Informational
- **Location:** `Dockerfile:75-98`, `docker-compose.yml:13-22`.
- **Finding:** `FROM scratch`, non-root `nonroot:nonroot` (uid/gid 65532), only the static binary
  + CA certs + `/data` volume present, read-only root filesystem, all caps dropped,
  `no-new-privileges`, tmpfs for `/tmp`. This is a best-practice runtime posture. Commendable.
