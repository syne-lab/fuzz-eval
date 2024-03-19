#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build_hostapd.sh
popd

echo "READY FOR FUZZING"