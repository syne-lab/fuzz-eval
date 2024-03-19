#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-openssl.sh
make clean
make
popd

echo "READY FOR FUZZING"