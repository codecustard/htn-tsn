# syntax=docker/dockerfile:1
# htn-tsn node image: tsn-node (default), plus the tsn CLI and tsn-coordinator.
#   docker build -t htn-tsn .
#   docker run --rm htn-tsn --help

FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin tsn-node --bin tsn --bin tsn-coordinator \
    && mkdir -p /out && cp target/release/tsn-node target/release/tsn target/release/tsn-coordinator /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data tsn && mkdir -p /data && chown tsn /data
COPY --from=build /out/ /usr/local/bin/
USER tsn
WORKDIR /data
VOLUME /data
EXPOSE 7001
ENTRYPOINT ["tsn-node"]
CMD ["run", "--dir", "/data", "--registry", "/etc/tsn/registry.json", "--listen", "0.0.0.0:7001"]
