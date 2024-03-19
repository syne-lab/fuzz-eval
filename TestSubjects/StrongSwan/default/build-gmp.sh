#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

rm -rf gmp-6.1.2
tar xvf gmp-6.1.2.tar.xz

pushd gmp-6.1.2
    mkdir -p build 
    ./configure --prefix=`pwd`/build
    make -j$cpuCnt
    make install
popd

echo "==> gmp-6.1.2 ready."; sleep 3