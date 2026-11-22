# Shopping Sessions: Rust release build for linux/amd64 scoring nodes.
FROM rust:1-slim-bookworm AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release --locked

FROM debian:bookworm-slim

# The scorer runs the container as uid 1000; give that uid a name and a home.
RUN useradd --uid 1000 --no-create-home --home-dir /scratch app

COPY --from=builder /src/target/release/shopping-sessions /app/shopping-sessions
COPY run.sh /app/run.sh
RUN chmod +x /app/shopping-sessions /app/run.sh

ENV DATA_DIR=/data \
    OUTPUT_DIR=/output \
    SCRATCH_DIR=/scratch \
    TMPDIR=/scratch \
    HOME=/scratch

WORKDIR /app
CMD ["/app/shopping-sessions"]
