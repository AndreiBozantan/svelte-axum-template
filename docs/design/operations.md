# Operations Design

## 1. Network Topology & Deployment Model

The application is designed to run behind a **TLS-terminating reverse proxy** (e.g., Nginx, Traefik, Caddy, or a Cloud provider load balancer). 

### HTTPS Enforcement
- The application itself binds to plain HTTP (`0.0.0.0:3000` by default).
- All SSL/TLS termination, HTTP-to-HTTPS redirection, and certificate management (such as Let's Encrypt) are delegated to the reverse proxy.
- **Important**: The application assumes that any request reaching it has already been validated and redirected to HTTPS by the reverse proxy.

### Client IP Extraction & Trusted Proxies
- To support accurate rate limiting and access logging, the application can extract the client's real IP address from proxy headers.
- **Header Parsing**: By default, the application extracts the IP from `X-Forwarded-For` or `X-Real-IP` headers **only** if the `trusted_proxy` flag is enabled under `[server]` in the configuration:
  ```toml
  [server]
  trusted_proxy = true
  ```
- **Security Control**: If `trusted_proxy` is `false` (default), the application completely ignores `X-Forwarded-For` and `X-Real-IP` headers to prevent IP spoofing attacks, falling back to the socket's connection peer IP.

---

## 2. Process Lifecycle & Graceful Shutdown

To support zero-downtime rolling updates in containerized environments (like Docker Compose, Kubernetes, or ECS), the application handles graceful shutdown signals.

### Signal Handling
- The server listens for both **SIGINT** (Ctrl+C) and **SIGTERM** signals.
- Upon receiving either signal:
  1. The server stops accepting new inbound connections.
  2. The server waits for all active, in-flight requests to complete (subject to the gateway timeout).
  3. The server closes database connection pools and exits cleanly.
- **Kubernetes / ECS Integration**: Container platforms send a `SIGTERM` first, followed by a `SIGKILL` after a grace period (typically 30 seconds). Handling `SIGTERM` guarantees that in-flight requests are not terminated abruptly.
