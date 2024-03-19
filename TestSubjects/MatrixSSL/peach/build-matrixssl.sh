#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`
rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

pushd $IMPL_NAME
    CC=$FUZZERCC CXX=$FUZZERCXX make -j$cpuCnt
    # # enable crypto trace for easy debugging
    # sed -i 's/\/\* #define USE_CRYPTO_TRACE \*\//#define USE_CRYPTO_TRACE/g' ./crypto/cryptoConfig.h

    # make -j$cpuCNT

popd

echo "Changing the last line in the library's Makefile"
python3 ./change_last_line.py

echo "==> $IMPL_NAME ready"; sleep 3
