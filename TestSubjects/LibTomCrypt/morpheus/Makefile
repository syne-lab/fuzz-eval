# Cyiu: based on the Makefile of the axTLS samples

_dummy := $(shell mkdir -p build)

all : libtomcrypt_harness

LTC_HOME=./libtomcrypt-1.18.2
LTM_HOME=./libtommath-1.2.0
INC=-I${LTC_HOME}/src/headers/

OBJ=libtomcrypt_harness.o



libtomcrypt_harness : $(OBJ) $(LTC_HOME)/libtomcrypt.a $(LTM_HOME)/libtommath.a
	$(FUZZERCXX) ./build/$(OBJ) $(LTC_HOME)/libtomcrypt.a $(LTM_HOME)/libtommath.a $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/libtomcrypt_harness
