# agat — single static binary in an empty image.
#
#   docker build -t agat .
#   docker run --rm --network none -v "$HOME/.agat:/data" -v "$PWD:/scan:ro" agat scan /scan
#   docker run --rm -p 127.0.0.1:8080:8080 -v "$HOME/.agat:/data" agat \
#     serve --listen 0.0.0.0:8080 --allow-remote      # HTTP API, host-loopback only
#
# The runtime image is `scratch`: no shell, no package manager, no
# network stack in use. agat makes no network calls; run it with
# `--network none` to prove that rather than take it on trust.

FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agat-cli \
 && mkdir -p /out/tmp /out/data \
 && cp target/release/agat /out/agat

FROM scratch
LABEL org.opencontainers.image.title="agat" \
      org.opencontainers.image.description="An adaptive immune system for binaries: offline detection of polymorphic, metamorphic, and AI-rewritten malware variants." \
      org.opencontainers.image.source="https://github.com/Armur-Ai/agat" \
      org.opencontainers.image.documentation="https://github.com/Armur-Ai/agat/blob/main/docs/GUIDE.md" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="Armur-Ai"
COPY --from=build --chown=65534:65534 /out/ /
# SQLite may spill temp files; `scratch` has no /tmp of its own.
ENV TMPDIR=/tmp \
    AGAT_HOME=/data
USER 65534:65534
VOLUME ["/data"]
EXPOSE 8080
WORKDIR /scan
ENTRYPOINT ["/agat"]
CMD ["--help"]
