# override default compiler with afl-clang
CC=$FUZZERCC CXX=$FUZZERCXX ./build-axtls.sh
sleep 2
CC=$FUZZERCC CXX=$FUZZERCXX ./copy-and-build-harness.sh
