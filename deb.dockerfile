ARG build_image
FROM $build_image AS build-stage

RUN apt-get update && apt-get install bzip2 --yes

# build static libmnl
WORKDIR /tmp/libmnl
RUN curl -sL https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 | tar jx --strip-components=1 && \
  ./configure --enable-static --disable-shared --prefix=/usr && \
  make -j CFLAGS="-fPIE -O3" && \
  make install

# build static libnftnl
WORKDIR /tmp/libnftnl
RUN curl -sL https://www.netfilter.org/pub/libnftnl/libnftnl-1.2.3.tar.bz2 | tar jx --strip-components=1 && \
  ./configure --enable-static --disable-shared --prefix=/usr && \
  make -j CFLAGS="-fPIE -O3" && \
  make install

# build static nftables
WORKDIR /tmp/nftables
RUN curl -sL https://www.netfilter.org/pub/nftables/nftables-1.0.5.tar.bz2 | tar jx --strip-components=1 && \
  ./configure --enable-static --disable-shared --with-mini-gmp --without-cli --prefix=/usr --disable-python && \
  make -j CFLAGS="-fPIE -O3" && \
  make install

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
