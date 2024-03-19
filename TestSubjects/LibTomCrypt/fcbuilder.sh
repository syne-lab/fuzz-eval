#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-ltc.sh
make clean
make
popd

echo "READY FOR FUZZING"