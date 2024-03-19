_dummy := $(shell mkdir -p build)
all : openssl1_harness

OPENSSL_HOME=./openssl-1.1.1k
INC=-I${OPENSSL_HOME}/include/

OBJ=openssl1_harness.o


LDFLAGS+= `python3.10-config --embed --ldflags`
CFLAGS+= `python3.10-config --embed --cflags`

openssl1_harness : $(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a 
	$(FUZZERCC) ./build/$(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a  $(LDFLAGS)  -ldl -o ./build/$@

%.o : %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openssl1_harness
	
