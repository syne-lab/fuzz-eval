#!/bin/bash

# written by Cyiu
rm -rf TEST
cp -r seeds TEST

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`
FLAGS=-fsanitize=fuzzer-no-link

rm -rf $IMPL_NAME
tar zxvf $IMPL_NAME.tar.gz

pushd $IMPL_NAME
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./
    mkdir build
    CC=$FUZZERCC CXX=$FUZZERCXX CFLAGS=$FLAGS CXXFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS ./Configure linux-x86_64 --prefix=`pwd`/build --openssldir=`pwd`/build no-threads no-hw 

    CC=$FUZZERCC CXX=$FUZZERCXX CFLAGS=$FLAGS CXXFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make -j$cpuCnt
    # make install # no need as we are overloading the 'test' dir

popd

echo "==> $IMPL_NAME ready"; sleep 3
