#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build-all.sh
popd

echo "READY FOR FUZZING"