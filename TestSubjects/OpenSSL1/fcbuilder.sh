#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-openssl1.sh
make clean
make
popd

echo "READY FOR FUZZING"