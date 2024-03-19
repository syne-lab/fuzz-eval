#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-mbedtls.sh
make clean
make
popd

echo "READY FOR FUZZING"