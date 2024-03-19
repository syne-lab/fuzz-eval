#!/bin/bash
echo "BUILDING LIBRARY"

pushd /target
./build_wpa_supplicant.sh
popd

echo "READY FOR FUZZING"