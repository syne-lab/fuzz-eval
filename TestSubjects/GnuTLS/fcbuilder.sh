#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-all.sh
make clean
make
popd

echo "READY FOR FUZZING"