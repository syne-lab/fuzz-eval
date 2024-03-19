#!/bin/bash

# written by Cyiu
rm -rf TEST
cp -r seeds TEST
source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`
FLAGS=-fsanitize=fuzzer-no-link

rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

pushd $IMPL_NAME
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./ -b /target/blocked_matrixssl
    CC=$FUZZERCC CXX=$FUZZERCXX CFLAGS=$FLAGS CXXFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make -j$cpuCnt

    # # enable crypto trace for easy debugging
    # sed -i 's/\/\* #define USE_CRYPTO_TRACE \*\//#define USE_CRYPTO_TRACE/g' ./crypto/cryptoConfig.h

    # make -j$cpuCNT

popd

echo "Changing the last line in the library's Makefile"
python3 ./change_last_line.py

echo "==> $IMPL_NAME ready"; sleep 3
