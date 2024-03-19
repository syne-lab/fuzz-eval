_dummy := $(shell mkdir -p build)

all : openssl_harness

OPENSSL_HOME=./openssl
INC=-I${OPENSSL_HOME}/include/

OBJ=openssl_harness.o

LDFLAGS= -lpthread -ldl  -lutil -lm -lm
openssl_harness : $(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a 
	$(FUZZERCXX) ./build/$(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a -ldl $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	echo ${LDFLAGS}
	echo ${CFLAGS}
	rm -f ./build/${OBJ} ./build/openssl_harness
	
