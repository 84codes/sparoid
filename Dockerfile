FROM 84codes/crystal:1.5.0-alpine-latest as builder
RUN apk add --no-cache nftables-dev
WORKDIR /tmp
COPY shard.yml shard.lock ./
RUN shards install --production
COPY src/ src/
RUN shards build --release --production --no-debug && strip bin/*

FROM alpine:latest
RUN apk add --no-cache libgcc libevent pcre libssl3 nftables
COPY --from=builder /tmp/bin/* /usr/bin/
ENTRYPOINT ["/usr/bin/sparoid-server"]
