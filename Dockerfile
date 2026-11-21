# Shopping Sessions: Rust release build for linux/amd64 scoring nodes.
FROM rust:1-slim-bookworm AS builder

WORKDIR /src

# Cache dependency compilation independently from src/ changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs \
    && RUSTFLAGS="-C target-cpu=x86-64-v2" cargo build --release --locked \
    && rm -rf src

COPY src/ ./src/
RUN touch src/main.rs \
    && RUSTFLAGS="-C target-cpu=x86-64-v2" cargo build --release --locked

FROM debian:bookworm-slim

# The scorer runs the container as uid 1000; give that uid a name and a home.
RUN useradd --uid 1000 --no-create-home --home-dir /scratch app

COPY --from=builder /src/target/release/shopping-sessions /app/shopping-sessions
COPY run.sh /app/run.sh
RUN chmod +x /app/shopping-sessions /app/run.sh

ENV TMPDIR=/scratch \
    HOME=/scratch

WORKDIR /app
CMD ["/app/run.sh"]
