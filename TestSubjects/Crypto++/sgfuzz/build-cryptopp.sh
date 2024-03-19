#!/bin/bash
rm -rf TEST
cp -r seeds TEST

dirName='cryptopp850'

rm -rf $dirName
unzip -o -d $dirName cryptopp850.zip


FLAGS=-fsanitize=fuzzer-no-link
cd $dirName
    python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./ -b /target/blocked_vars
    CC=$FUZZERCC CXX=$FUZZERCXX CXXFLAGS=$FLAGS CFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS  make -j6

cd -
