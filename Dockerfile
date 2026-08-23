# =============================================================================
# UGENT WeChat Proxy - Dockerfile
# =============================================================================

# On an Apple Silicon host, produce a linux/amd64 binary with:
#
#   docker buildx build --platform linux/amd64 \
#     --target export --output type=local,dest=dist .
#
# OrbStack runs the amd64 build under Rosetta. For a runnable image instead of
# a bare binary, drop --target/--output and use --load.

# Must be >= the crate's rust-version (Cargo.toml). This was pinned at 1.83,
# which cannot build an edition-2024 crate.
ARG RUST_VERSION=1.96

# Build stage
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src

# Build the actual binary
RUN touch src/main.rs && cargo build --release

# =============================================================================
# Export stage: bare binary, for --output type=local
# =============================================================================
FROM scratch AS export
COPY --from=builder /app/target/release/ugent-wechat-proxy /

# =============================================================================
# Runtime stage
# =============================================================================
FROM debian:bookworm-slim AS runtime

# ca-certificates for HTTPS; curl is what HEALTHCHECK below shells out to.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ugent

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/ugent-wechat-proxy /usr/local/bin/

# Set ownership
RUN chown -R ugent:ugent /app

# Switch to non-root user
USER ugent

# OA webhook, worker WebSocket, WeCom callback.
EXPOSE 8080 8081 8082

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the proxy
CMD ["ugent-wechat-proxy"]
