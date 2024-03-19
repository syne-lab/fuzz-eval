#!/bin/bash

rm -rf gnutls-3.6.15
tar xvf gnutls-3.6.15.tar.xz

NETTLE_HOME=`pwd`/nettle-3.7.2
GMP_HOME=`pwd`/gmp-6.1.2/build

pushd gnutls-3.6.15

    mkdir build

    CFLAGS+=" -I$NETTLE_HOME/build/include -I$GMP_HOME/include -fsanitize=fuzzer-no-link"; export CFLAGS;
    LDFLAGS+=" -L$NETTLE_HOME -L$GMP_HOME/lib -fsanitize=fuzzer-no-link"; export LDFLAGS;

	NETTLE_CFLAGS="-I$NETTLE_HOME" \
	NETTLE_LIBS="-L$NETTLE_HOME -lnettle" \
	HOGWEED_CFLAGS="-I$NETTLE_HOME" \
	HOGWEED_LIBS="-L$NETTLE_HOME -lhogweed" \
	GMP_LIBS="-L$GMP_HOME/lib -lgmp" \
	GMP_CFLAGS="-I$GMP_HOME/include" \
	./configure --disable-doc \
		--with-included-libtasn1 \
		--with-included-unistring \
		--without-p11-kit \
		--without-idn \
		--without-tpm \
		--without-zlib \
		--enable-static=yes \
		--enable-shared=no \
		--disable-tools \
		--disable-dhe \
		--disable-ecdhe \
		--disable-ocsp \
		--disable-gost \
		--disable-non-suiteb-curves \
		--prefix=`pwd`/build

    make -j

    make install

popd

