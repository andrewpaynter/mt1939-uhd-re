# Standalone MakeMKV CLI + sdftool, for drive identification/flashing. Not used by ARM.
# You must accept the MakeMKV EULA yourself before building/using this image.
FROM ubuntu:22.04
ARG V=2.0.0
ARG BASE=https://www.makemkv.com/download
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config ca-certificates curl libc6-dev libssl-dev libexpat1-dev \
      libavcodec-dev zlib1g-dev less \
 && cd /tmp && for p in oss bin; do curl -fsSLO "$BASE/makemkv-$p-$V.tar.gz" || curl -fsSLO "$BASE/old/makemkv-$p-$V.tar.gz"; tar xzf makemkv-$p-$V.tar.gz; done \
 && cd /tmp/makemkv-oss-$V && ./configure --disable-gui && make -j8 && make install \
 && cd /tmp/makemkv-bin-$V && mkdir -p tmp && echo accepted > tmp/eula_accepted && make install \
 && rm -rf /tmp/makemkv-* /var/lib/apt/lists/*
