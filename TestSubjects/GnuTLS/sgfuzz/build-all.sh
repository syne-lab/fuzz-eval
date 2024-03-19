#!/bin/bash
rm -rf TEST
cp -r seeds TEST

FLAGS=-fsanitize=fuzzer-no-link

./build-gmp.sh
sleep 2
./build-nettle.sh
sleep 2
CC=$FUZZERCC CXX=$FUZZERCXX CFLAGS=$FLAGS CXXFLAGS=$FLAGS CPPFLAGS=$FLAGS LDFLAGS=$FLAGS ./build-gnutls.sh