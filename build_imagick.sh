#!/bin/bash
export NM="gcc-nm"
export RANLIB="gcc-ranlib"
export AR="gcc-ar"
export LDFLAGS="-flto -static -O2 -lpthread -Lstatic_libs"
export CFLAGS="-flto -static -O2"

autoreconf -vi

#--with-png --with-webp --with-jpeg \

./configure \
  --without-x \
  --disable-openmp --disable-opencl \
  --without-threads --disable-thread --without-modules \
  --disable-shared --enable-static --enable-delegate-build \
  --without-xml --without-jbig \
  --without-magick-plus-plus \
  --without-umem --without-jemalloc \
  --without-freetype --without-fontconfig --without-raqm \
  --without-raw --without-wmf --without-tiff --without-djvu \
  --without-heic --without-gvc --without-flif \
  --without-openexr --without-fpx --without-dps \
  --without-pango --without-rsvg \
  --without-openjp2 \
  --enable-zero-configuration \
  --disable-docs no_x=yes

make -j 6 V=1

