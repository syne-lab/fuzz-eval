#!/bin/bash

targetDIR='Botan-2.17.3'


rm -rf $targetDIR


tar xvf $targetDIR.tar.xz
python3 ./change_first_line.py


cd $targetDIR

    CC=$FUZZERCC CXX=$FUZZERCXX ./configure.py --prefix=`pwd` --without-documentation --enable-static-library --disable-shared-library
    CC=$FUZZERCC CXX=$FUZZERCXX make -j6
    CC=$FUZZERCC CXX=$FUZZERCXX make check
    CC=$FUZZERCC CXX=$FUZZERCXX make install

cd -
