#!/bin/bash

rm -rf nettle-3.7.2
tar xvf nettle-3.7.2.tar.gz

GMP_HOME=`pwd`/gmp-6.1.2/build

echo $GMP_HOME

pushd nettle-3.7.2

    mkdir -p build

    CFLAGS+=" -I$GMP_HOME/include"; export CFLAGS
    LDFLAGS+=" -L$GMP_HOME/lib"; export LDFLAGS

    ./configure --prefix=`pwd`/build --disable-openssl
    
    make -j

    make install

popd

