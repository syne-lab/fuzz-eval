#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

rm -rf $IMPL_NAME
tar zxvf $IMPL_NAME.tar.gz

pushd $IMPL_NAME

    mkdir build
    CC=$FUZZERCC CXX=$FUZZERCXX ./Configure linux-x86_64 --prefix=`pwd`/build --openssldir=`pwd`/build no-threads no-hw 

    CC=$FUZZERCC CXX=$FUZZERCXX make -j$cpuCnt
    # make install # no need as we are overloading the 'test' dir

popd

echo "==> $IMPL_NAME ready"; sleep 3
