ARG build_image
FROM $build_image AS build-stage

RUN apt-get update && apt-get install bzip2 libssl-dev --yes

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
