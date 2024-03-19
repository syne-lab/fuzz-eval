# Cyiu: based on the Makefile of the axTLS samples

_dummy := $(shell mkdir -p build)

all : libtomcrypt_harness

LTC_HOME=./libtomcrypt-1.18.2
LTM_HOME=./libtommath-1.2.0
INC=-I${LTC_HOME}/src/headers/

OBJ=libtomcrypt_harness.o

LDFLAGS=`python3.10-config --embed --ldflags`
CFLAGS=`python3.10-config --embed --cflags`

libtomcrypt_harness : $(OBJ) $(LTC_HOME)/libtomcrypt.a $(LTM_HOME)/libtommath.a
	$(FUZZERCXX)  -fsanitize=fuzzer ./build/$(OBJ) $(LTC_HOME)/libtomcrypt.a $(LTM_HOME)/libtommath.a $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c -std=c++11 $(CFLAGS) -fsanitize=fuzzer $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/libtomcrypt_harness
