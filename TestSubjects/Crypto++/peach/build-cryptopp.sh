#!/bin/bash

dirName='cryptopp850'

rm -rf $dirName
unzip -o -d $dirName cryptopp850.zip
cd $dirName
    CC=$FUZZERCC CXX=$FUZZERCXX make -j6
cd -
