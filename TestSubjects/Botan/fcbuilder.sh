#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-botan.sh
make clean
make
popd

echo "READY FOR FUZZING"