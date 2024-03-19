#!/bin/bash

rm -rf gmp-6.1.2
tar xvf gmp-6.1.2.tar.xz

pushd gmp-6.1.2

    mkdir -p build; ./configure --prefix=`pwd`/build
    
    make -j
    make install

popd

