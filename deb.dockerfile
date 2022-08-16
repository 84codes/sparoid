ARG build_image
FROM $build_image AS build-stage
WORKDIR /build

# Copy all files
COPY shard.yml shard.lock README.md LICENSE ./
COPY src src
COPY build build

# Build deb package
RUN build/deb

# Copy the deb package to a scratch image, that then can be exported
FROM scratch AS export-stage
COPY --from=build-stage /build/builds .
