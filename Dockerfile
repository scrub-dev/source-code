# Multi-stage build → static musl binary in a minimal scratch image.
# TLS uses rustls + bundled webpki roots, so no system CA store is required;
# custom/internal CAs are supplied via config file paths (mounted volumes).

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
# rust:alpine targets x86_64-unknown-linux-musl by default (fully static).
RUN cargo build --release -p scrub && strip target/release/scrub

FROM scratch
COPY --from=build /src/target/release/scrub /scrub
# Run as a non-root numeric UID (no user db in scratch).
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/scrub"]
CMD ["--config", "/etc/scrub/scrub.yaml", "--listen", "0.0.0.0:8080"]
