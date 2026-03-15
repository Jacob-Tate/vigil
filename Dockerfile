# ── Stage 1: Build the React client ──────────────────────────────────────────
FROM node:24-alpine AS client-build
WORKDIR /build
COPY client/package*.json ./client/
RUN npm ci --prefix client
COPY client/ ./client/
RUN npm run build --prefix client

# ── Stage 2: Build the Rust server ───────────────────────────────────────────
FROM rust:1-slim-bookworm AS server-build
WORKDIR /build

# Cache dependency compilation by building a stub binary first.
# The real source is compiled in the second cargo build below.
COPY vigil/Cargo.toml vigil/Cargo.lock ./vigil/
RUN mkdir -p vigil/src && echo 'fn main() {}' > vigil/src/main.rs \
    && cargo build --release --manifest-path vigil/Cargo.toml \
    && rm -f vigil/target/release/deps/vigil*

# Build the real source
COPY vigil/src ./vigil/src
RUN cargo build --release --manifest-path vigil/Cargo.toml

# ── Stage 3: Minimal production image ────────────────────────────────────────
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY --from=server-build /build/vigil/target/release/vigil ./vigil
COPY --from=client-build /build/client/dist ./client/dist

ENV PORT=3001
ENV DATA_DIR=data
ENV NODE_ENV=production

EXPOSE 3001
VOLUME ["/app/data"]

CMD ["./vigil"]
