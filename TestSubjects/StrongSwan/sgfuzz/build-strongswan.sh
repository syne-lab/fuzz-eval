#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`
# now build strongswan

rm -rf ./$IMPL_NAME
tar xvf $IMPL_NAME.tar.bz2

pushd $IMPL_NAME
    ./configure --enable-monolithic \
    --enable-static --disable-shared \
    --disable-kernel-netlink  \
    --with-mpz_powm_sec=no 

    # # need to fix the config.h for some library functions that we don't have
    # sed -i 's!^#define HAVE_QSORT_R!#undef HAVE_QSORT_R!g' config.h
    # echo "#define NO_CHECK_MEMWIPE" >> config.h
    echo "Instrumenting...."
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./ -b /target/blocked_strongswan
    echo "Instrumenting....Done"
    sleep 2
    make -j$cpuCnt

popd
