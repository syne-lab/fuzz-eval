#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

# build LTM first
LTM=libtommath-1.2.0

rm -rf $LTM
unzip $LTM.zip

pushd $LTM

     make -j$cpuCnt

popd
sleep 2
# then LTC
rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

pushd $IMPL_NAME

    CC=$FUZZERCC CXX=$FUZZERCXX make CFLAGS="-DUSE_LTM -DLTM_DESC -I${ScriptDir}/${LTM}" EXTRALIBS="${ScriptDir}/${LTM}/libtommath.a" library -j$cpuCnt

popd

echo "==> $IMPL_NAME ready"


# Call this script with suitable CC=..., CXX=.. paths for compiling with different versions of AFL instrumentations
