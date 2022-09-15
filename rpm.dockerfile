ARG build_image
FROM $build_image AS build-stage

# Install deps
RUN dnf install -y rpmdevtools rpmlint git systemd-rpm-macros nftables-devel libmnl-devel libnftnl-devel

# Copy all files
WORKDIR /tmp/sparoid
COPY shard.yml shard.lock README.md LICENSE CHANGELOG.md ./
COPY src src
COPY extras extras

# Build package
WORKDIR /tmp
COPY build/rpm .
RUN ./rpm

# Copy the deb package to a scratch image, that then can be exported
FROM scratch AS export-stage
COPY --from=build-stage /tmp/builds .
