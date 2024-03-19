#!/bin/bash

# written by Cyiu
rm -rf TEST
cp -r seeds TEST

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

# build LTM first
LTM=libtommath-1.2.0

rm -rf $LTM
unzip $LTM.zip

pushd $LTM
    
    make -j$cpuCnt

popd

# then LTC
rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

pushd $IMPL_NAME
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./
    CC=$FUZZERCC CXX=$FUZZERCXX make CFLAGS="-fsanitize=fuzzer-no-link -DUSE_LTM -DLTM_DESC -I${ScriptDir}/${LTM}" EXTRALIBS="${ScriptDir}/${LTM}/libtommath.a" library -j$cpuCnt

popd

echo "==> $IMPL_NAME ready"



