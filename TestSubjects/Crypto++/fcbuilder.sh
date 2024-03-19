#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-cryptopp.sh
make clean
make
popd

echo "READY FOR FUZZING"