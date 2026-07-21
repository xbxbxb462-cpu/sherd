# Dockerfile — isolated build environment for sherd.
#
# Builds the release binary inside a clean container so that NO
# developer-machine paths leak into the binary, regardless of the
# host's directory layout. The resulting binary is copied into a
# scratch image (zero leftover build tools).
#
# Usage:
#   docker build -t sherd .
#   docker cp $(docker create sherd):/sherd ./sherd
#
# Then verify:
#   strings ./sherd | grep -iE '(/home/|/Users/|cargo/registry)'
#   # Expected: no output

FROM rust:1.85-slim AS builder

# Avoid apt cache bloat; we only need ca-certificates for the cargo
# registry fetch (https).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the project. .dockerignore (if present) should exclude target/
# and .git/ to keep the build context small.
COPY . .

# Build with full path remapping. Inside the container, the source lives
# under /build, so we remap that to "." — the binary will contain only
# relative paths like "./src/main.rs" and "index.crates.io/<crate>".
# Note: dependency folder names (e.g. `argon2-0.5.3`) still appear
# because they are part of cargo's per-crate source directory name.
# This is a fundamental cargo limitation; the only way to remove them
# is to vendor dependencies into a flat directory and remap each one
# individually (out of scope for this Dockerfile).
ENV RUSTFLAGS="\
--remap-path-prefix=/build=. \
--remap-path-prefix=/usr/local/cargo/registry/src=index.crates.io \
--remap-path-prefix=/usr/local/cargo=./cargo \
--remap-path-prefix=/usr/local/rustup=./rustup \
-C debuginfo=0 \
-C link-args=-Wl,-s"

ENV SOURCE_DATE_EPOCH=0
ENV CARGO_TERM_QUIET=true

RUN cargo build --release \
 && strip --strip-all target/release/sherd

# Stage 2: scratch image with ONLY the binary. No shell, no package
# manager, no leftover source — nothing for an adversary to inspect.
FROM scratch
COPY --from=builder /build/target/release/sherd /sherd

# Entry point is the binary itself. Run with:
#   docker run --rm sherd --help
ENTRYPOINT ["/sherd"]
CMD ["--help"]
