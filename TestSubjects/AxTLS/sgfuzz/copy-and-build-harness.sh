#!/bin/bash

# written by Cyiu

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

HARNESSDIR='test-harness'

# inject and build test harness
cp -r $HARNESSDIR $IMPL_NAME

pushd $IMPL_NAME
    echo "Instrumenting for SGFuzz..."
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./
    echo "Instrumenting for SGFuzz Done"
    sleep 2
    make -j$cpuCnt
popd

pushd $IMPL_NAME/$HARNESSDIR
    echo "Instrumenting for SGFuzz..."
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./
    echo "Instrumenting for SGFuzz Done"
    sleep 2
    make -j$cpuCnt
    ret_code=$?
popd

if [ $ret_code != 0 ]; then
    printf "\n[ERROR] make failed with return code [%d]; pls check your test harness\n" $ret_code
    exit $ret_code
else
    printf "\n[INFO] test harness built in $IMPL_NAME/$HARNESSDIR\n"
fi


