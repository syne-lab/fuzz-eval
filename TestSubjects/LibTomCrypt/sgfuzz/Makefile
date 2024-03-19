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
	$(FUZZERCXX) -fsanitize=fuzzer-no-link ./build/$(OBJ) $(LTC_HOME)/libtomcrypt.a $(LTM_HOME)/libtommath.a /SGFuzz/libsfuzzer.a  $(LDFLAGS)  -ldl -lpthread -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS) -fsanitize=fuzzer-no-link $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/libtomcrypt_harness
