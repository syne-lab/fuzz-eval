#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-matrixssl.sh
make clean
make
popd

echo "READY FOR FUZZING"