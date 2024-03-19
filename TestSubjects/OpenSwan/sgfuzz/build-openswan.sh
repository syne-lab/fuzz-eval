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
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./ -b /target/blocked_openswan
    CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make -j$cpuCnt programs

popd

echo "==> $IMPL_NAME ready"

