./build-gmp.sh
sleep 2
./build-nettle.sh
sleep 2
CC=$FUZZERCC CXX=$FUZZERCXX ./build-gnutls.sh