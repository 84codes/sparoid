FROM 84codes/crystal:1.4.1-alpine-latest as builder
WORKDIR /tmp
COPY shard.yml shard.lock ./
RUN shards install --production
COPY src/ src/
RUN shards build --release --production --static --no-debug

FROM debian:11 AS deb-builder
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y binutils
WORKDIR /tmp
COPY --from=builder /tmp/bin bin
COPY README.md CHANGELOG.md LICENSE .
COPY build/deb .
ARG deb_revision=1
RUN sh -eux deb ${deb_revision}

FROM scratch AS deb
COPY --from=deb-builder /tmp/*.deb .

FROM scratch
COPY --from=builder /tmp/bin/ /
ENTRYPOINT ["/sparoid-server"]
