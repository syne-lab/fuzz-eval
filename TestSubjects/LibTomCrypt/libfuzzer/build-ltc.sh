#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

# build LTM first
LTM=libtommath-1.2.0

rm -rf $LTM
unzip $LTM.zip

FLAGS=-fsanitize=fuzzer-no-link

pushd $LTM

    make -j$cpuCnt

popd

# then LTC
rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

pushd $IMPL_NAME

    CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make CFLAGS="-fsanitize=fuzzer-no-link -DUSE_LTM -DLTM_DESC -I${ScriptDir}/${LTM}" EXTRALIBS="${ScriptDir}/${LTM}/libtommath.a" library -j$cpuCnt

popd

echo "==> $IMPL_NAME ready"

rm -rf TEST
cp -r seeds TEST


# Call this script with suitable CC=..., CXX=.. paths for compiling with different versions of AFL instrumentations
