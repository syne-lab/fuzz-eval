#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

# now build strongswan

rm -rf ./$IMPL_NAME
tar xvf $IMPL_NAME.tar.bz2

pushd $IMPL_NAME
./configure --enable-monolithic \
    --enable-static \
    --disable-kernel-netlink  \
    --with-mpz_powm_sec=no 

    # # need to fix the config.h for some library functions that we don't have
    # sed -i 's!^#define HAVE_QSORT_R!#undef HAVE_QSORT_R!g' config.h
    # echo "#define NO_CHECK_MEMWIPE" >> config.h

make -j$cpuCnt

popd
