#!/bin/bash

rm -rf TEST
cp -r seeds TEST

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`

targetDIR='Botan-2.17.3'


rm -rf $targetDIR


tar xvf $targetDIR.tar.xz
python3 ./change_first_line.py

FLAGS=-fsanitize=fuzzer-no-link

rm -rf TEST
cp -r seeds TEST


cd $targetDIR

    CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS ./configure.py --prefix=`pwd` --without-documentation --enable-static-library --disable-shared-library --cxxflags -fsanitize=fuzzer-no-link --ldflags -fsanitize=fuzzer-no-link
    CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make -j$cpuCnt
    # CC=$FUZZERCC CXX=$FUZZERCXX make check
    CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS make install

cd -
