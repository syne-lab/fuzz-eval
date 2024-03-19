#!/bin/bash

rm -rf TEST
cp -r seeds TEST

source ./scripts-commons.sh
cpuCnt=`getCpuThreadCnts`


FLAGS=-fsanitize=fuzzer-no-link

rm -rf ./openssl
unzip openssl-c74188e.zip
mv ./openssl-c74188e86c78c4fa47c4a658e1355c40524fadb4 ./openssl
pushd ./openssl
	CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS  ./config no-shared
	make clean
	make -j$cpuCnt
popd
