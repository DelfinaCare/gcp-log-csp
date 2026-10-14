FROM rust:1.99.0-slim@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

# Set Rust target based on Docker target architecture
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      echo "aarch64-unknown-linux-musl" > /rust-target; \
    else \
      echo "x86_64-unknown-linux-musl" > /rust-target; \
    fi && \
    rustup target add $(cat /rust-target)

WORKDIR /app

# Cache dependency build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target $(cat /rust-target)
RUN rm -rf src

# Build the actual application
COPY src ./src
RUN touch src/main.rs && cargo build --release --target $(cat /rust-target) && \
    cp target/$(cat /rust-target)/release/gcp-log-csp /gcp-log-csp-bin

FROM scratch
COPY --from=builder /gcp-log-csp-bin /gcp-log-csp
ENTRYPOINT ["/gcp-log-csp"]
