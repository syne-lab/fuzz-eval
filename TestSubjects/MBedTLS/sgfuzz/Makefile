_dummy := $(shell mkdir -p build)

all : mbedtls_harness

MBED_HOME=./mbedtls-2.26.0
INC=-I${MBED_HOME}/include/

OBJ=mbedtls_harness.o
FLAGS=-fsanitize=fuzzer-no-link
LDFLAGS+=`python3.10-config --embed --ldflags`
CFLAGS+=`python3.10-config --embed --cflags`

mbedtls_harness : $(OBJ) $(MBED_HOME)/library/libmbedcrypto.a $(MBED_HOME)/library/libmbedx509.a $(MBED_HOME)/library/libmbedtls.a
	$(FUZZERCXX) ./build/$(OBJ) $(MBED_HOME)/library/libmbedcrypto.a $(MBED_HOME)/library/libmbedx509.a $(MBED_HOME)/library/libmbedtls.a -fsanitize=fuzzer-no-link /SGFuzz/libsfuzzer.a  $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS) -fsanitize=fuzzer-no-link $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/mbedtls_harness
