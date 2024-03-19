_dummy := $(shell mkdir -p build)

all : mbedtls_harness

MBED_HOME=./mbedtls-2.26.0
INC=-I${MBED_HOME}/include/

OBJ=mbedtls_harness.o


mbedtls_harness : $(OBJ) $(MBED_HOME)/library/libmbedcrypto.a $(MBED_HOME)/library/libmbedx509.a $(MBED_HOME)/library/libmbedtls.a
	$(FUZZERCXX) ./build/$(OBJ) $(MBED_HOME)/library/libmbedcrypto.a $(MBED_HOME)/library/libmbedx509.a $(MBED_HOME)/library/libmbedtls.a $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/mbedtls_harness
