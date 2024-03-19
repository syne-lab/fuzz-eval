#!/bin/bash

# written by Cyiu
rm -rf TEST
cp -r seeds TEST


source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

FLAGS=-fsanitize=fuzzer-no-link

pushd $IMPL_NAME

    CC=$FUZZERCC CXX=$FUZZERCXXCXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make -j$cpuCnt programs

popd

echo "==> $IMPL_NAME ready"

