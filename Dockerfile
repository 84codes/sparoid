FROM 84codes/crystal:1.4.1-alpine-latest as builder
WORKDIR /tmp
COPY shard.yml shard.lock ./
RUN shards install --production
COPY src/ src/
RUN shards build --release --production --static --no-debug
RUN strip bin/*

FROM scratch
COPY --from=builder /tmp/bin/ /
ENTRYPOINT ["/sparoid-server"]
