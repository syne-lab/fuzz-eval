_dummy := $(shell mkdir -p build)
all : openssl1_harness

OPENSSL_HOME=./openssl-1.1.1k
INC=-I${OPENSSL_HOME}/include/

OBJ=openssl1_harness.o
LDFLAGS= -lpthread -ldl  -lutil -lm -lm
openssl1_harness : $(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a 
	$(FUZZERCXX) ./build/$(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a -ldl $(LDFLAGS) -o ./build/$@

%.o : %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openssl1_harness
	
