# agat — single static binary in an empty image.
#
#   docker build -t agat .
#   docker run --rm --network none -v "$HOME/.agat:/data" -v "$PWD:/scan:ro" agat scan /scan
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
COPY --from=build --chown=65534:65534 /out/ /
# SQLite may spill temp files; `scratch` has no /tmp of its own.
ENV TMPDIR=/tmp \
    AGAT_HOME=/data
USER 65534:65534
VOLUME ["/data"]
WORKDIR /scan
ENTRYPOINT ["/agat"]
CMD ["--help"]
