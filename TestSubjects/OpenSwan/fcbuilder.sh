#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target

./build-openswan.sh
make clean
make
popd

echo "READY FOR FUZZING"