#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

rm -rf $IMPL_NAME
tar zxvf $IMPL_NAME.tar.gz
mv axtls-code $IMPL_NAME

sleep 3

cp ./linuxconfig $IMPL_NAME/config/

pushd $IMPL_NAME

    # patch the PKCS1 portion so our test harness would work
    patch -p2 < ../pkcs1sighack.patch
    
    echo "Instrumenting for SGFuzz..."
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./
    echo "Instrumenting for SGFuzz Done"
    sleep 2
    make linuxconf -j$cpuCnt

popd


echo "==> $IMPL_NAME ready"



