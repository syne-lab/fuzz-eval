#!/bin/bash
rm -rf TEST
cp -r seeds TEST
FLAGS=-fsanitize=fuzzer-no-link
./build-gmp.sh
CC=$FUZZERCC CXX=$FUZZERCXX CFLAGS=$FLAGS CPPFLAGS=$FLAGS CXXFLAGS=$FLAGS LDFLAGS=$FLAGS ./build-strongswan.sh