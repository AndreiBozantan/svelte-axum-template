# syntax=docker/dockerfile:1

# --- Stage 1: Frontend Builder ---
FROM node:24-bookworm-slim@sha256:03eae3ef7e88a9de535496fb488d67e02b9d96a063a8967bae657744ecd513f2 AS frontend-builder
WORKDIR /build

# Copy only package manifests to cache dependencies
COPY frontend/package.json frontend/package-lock.json ./frontend/

# Install dependencies (cached unless package.json/package-lock.json changes)
RUN cd frontend && npm ci

# Copy the rest of the frontend source
COPY frontend/ ./frontend/

# Build the frontend (outputs to frontend/dist)
RUN cd frontend && npm run build


# --- Stage 2: Backend Builder (Dependency Cache) ---
FROM rust:1.96.0-alpine3.24@sha256:f87aa870663e2b57ec8c69de82c7eedf7383bee987eef7612c0359635eaadb41 AS backend-dependencies
WORKDIR /build

# Install alpine compilation packages
RUN apk add --no-cache \
    build-base \
    pkgconfig \
    sqlite-dev \
    sqlite \
    clang \
    lld

# Create a nonroot user and group for the scratch runtime
RUN addgroup -g 65532 nonroot && adduser -u 65532 -G nonroot -S -s /sbin/nologin nonroot

# Copy cargo configuration files
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml backend/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml

# Create a dummy main.rs to build and cache dependencies
RUN mkdir -p backend && echo "fn main() {}" > backend/main.rs
RUN mkdir -p xtask/src && echo "fn main() {}" > xtask/src/main.rs

# Build dependencies only (compiles natively to host's MUSL architecture by default)
ENV RUSTC_WRAPPER=""
RUN cargo build --release --bin app

# Create a pristine empty directory for runtime data
RUN mkdir -p /tmp/empty_data


# --- Stage 3: Backend Builder (Final Compilation) ---
FROM backend-dependencies AS backend-builder

# Copy the frontend build output so rust-embed can compile it
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Copy the migrations and SQLx offline preparation metadata
COPY migrations ./migrations
COPY .sqlx ./.sqlx

# Copy the actual backend source code
COPY backend ./backend

# Touch the dummy source file to force cargo to rebuild our binary with the real code
RUN touch backend/main.rs

# Compile the actual application in offline mode
ENV SQLX_OFFLINE=true
ENV RUSTC_WRAPPER=""
RUN cargo build --release --bin app


# --- Stage 4: Runtime (from scratch) ---
FROM scratch

# Copy users and groups from builder
COPY --from=backend-builder /etc/passwd /etc/passwd
COPY --from=backend-builder /etc/group /etc/group

# Use the nonroot system user
USER nonroot:nonroot

# Copy SSL certificates from the builder stage (reqwest needs these for TLS validation)
COPY --from=backend-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the compiled static binary from the backend-builder stage
COPY --from=backend-builder /build/target/release/app /usr/local/bin/app

# Copy the pristine empty directory and map it to /data with nonroot ownership
COPY --from=backend-builder --chown=nonroot:nonroot /tmp/empty_data /data

# Start the application
WORKDIR /
EXPOSE 3000
VOLUME ["/data"]
CMD ["app"]
