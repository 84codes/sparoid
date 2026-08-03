ARG build_image
FROM $build_image AS build-stage

# Link against the distribution's libnftables rather than statically bundling
# a pinned build. The bundled versions (nftables 1.0.5 / libnftnl 1.2.3 /
# libmnl 1.0.5, pinned in 2022) segfault on Ubuntu 26.04, which ships nftables
# 1.1.6: nft_run_cmd_from_buffer crashes as soon as it parses a ruleset created
# by the newer userspace. Using the distro package keeps the linked library in
# step with the nftables that is actually installed on the host.
RUN apt-get update && apt-get install bzip2 libssl-dev libnftables-dev libnftnl-dev libmnl-dev --yes

WORKDIR /tmp/sparoid
# Copy all files
COPY shard.yml shard.lock README.md LICENSE ./
COPY src src
COPY build build

# Build deb package
RUN build/deb

# Copy the deb package to a scratch image, that then can be exported
FROM scratch AS export-stage
COPY --from=build-stage /tmp/sparoid/builds .
