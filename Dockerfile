FROM rust:1.99.1-slim@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

# Set Rust target based on Docker target architecture
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      echo "aarch64-unknown-linux-musl" > /rust-target; \
    else \
      echo "x86_64-unknown-linux-musl" > /rust-target; \
    fi && \
    rustup target add $(cat /rust-target)

# cargo-auditable embeds the dependency tree (crate names and versions) in the
# binary, so vulnerability scanners and SBOM tools can see what was compiled
# into it even though the final image has no package database. It is built
# from the versions locked in tools/Cargo.lock.
COPY tools tools
RUN cargo build --release --locked --manifest-path tools/Cargo.toml -p cargo-auditable --bin cargo-auditable && \
    cp tools/target/release/cargo-auditable /usr/local/cargo/bin/

WORKDIR /app

# Cache dependency build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo auditable build --release --target $(cat /rust-target)
RUN rm -rf src

# Build the actual application
COPY src ./src
RUN touch src/main.rs && cargo auditable build --release --target $(cat /rust-target) && \
    cp target/$(cat /rust-target)/release/gcp-log-csp /gcp-log-csp-bin

FROM scratch
COPY --from=builder /gcp-log-csp-bin /gcp-log-csp
ENTRYPOINT ["/gcp-log-csp"]
