FROM 84codes/crystal:latest-alpine AS builder
RUN apk add --no-cache nftables-dev libnftnl-dev libmnl-dev
WORKDIR /tmp
COPY shard.yml shard.lock ./
RUN shards install --production
COPY src/ src/
RUN shards build --release --production --no-debug && strip bin/*

FROM alpine:latest
RUN apk add --no-cache libgcc libevent pcre2 libssl3 nftables
COPY --from=builder /tmp/bin/* /usr/bin/
ENTRYPOINT ["/usr/bin/sparoid-server"]
