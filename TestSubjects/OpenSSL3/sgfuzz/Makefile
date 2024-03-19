_dummy := $(shell mkdir -p build)

all : openssl_harness

OPENSSL_HOME=./openssl
INC=-I${OPENSSL_HOME}/include/

OBJ=openssl_harness.o
LDFLAGS=`python3.10-config --embed --ldflags`
CFLAGS=`python3.10-config --embed --cflags`


openssl_harness : $(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a 
	$(FUZZERCXX) -fsanitize=fuzzer-no-link ./build/$(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a /SGFuzz/libsfuzzer.a -ldl $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS)  -fsanitize=fuzzer-no-link $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openssl_harness
	
