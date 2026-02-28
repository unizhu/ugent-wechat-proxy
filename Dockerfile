# =============================================================================
# UGENT WeChat Proxy - Dockerfile
# =============================================================================

# Build stage
FROM rust:1.83-bookworm AS builder

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
# Runtime stage
# =============================================================================
FROM debian:bookworm-slim

# Install ca-certificates for HTTPS
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
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

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the proxy
CMD ["ugent-wechat-proxy"]
