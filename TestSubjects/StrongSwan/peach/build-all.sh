#!/bin/bash
./build-gmp.sh
CC=$FUZZERCC CXX=$FUZZERCXX ./build-strongswan.sh