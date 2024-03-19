#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

rm -rf $IMPL_NAME
unzip $IMPL_NAME.zip

pushd $IMPL_NAME/library

    CC=$FUZZERCC CXX=$FUZZERCXX make -j$cpuCnt

popd

echo "==> $IMPL_NAME ready"
