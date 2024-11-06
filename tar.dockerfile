FROM 84codes/crystal:1.5.0-alpine-latest AS build-stage
WORKDIR /tmp
COPY shard.yml shard.lock README.md LICENSE ./
RUN shards install --production
COPY src src
RUN shards build --release --production --no-debug --static -Dwithout_nftables && strip bin/*
ARG pkg_revision=1
RUN tar zcvf "sparoid-$(shards version)-${pkg_revision}.$(uname -m)-static.tar.gz" \
    LICENSE README.md bin/*

# Copy the tar to a scratch image, that then can be exported
FROM scratch AS export-stage
COPY --from=build-stage /tmp/*.tar.gz .
