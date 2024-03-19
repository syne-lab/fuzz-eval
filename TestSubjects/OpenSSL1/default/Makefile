_dummy := $(shell mkdir -p build)
all : openssl1_harness

OPENSSL_HOME=./openssl-1.1.1k
INC=-I${OPENSSL_HOME}/include/

OBJ=openssl1_harness.o

# LDFLAGS+=-lpython3.10 -lcrypt -ldl  -lm -lm
# CFLAGS+=-I/usr/include/python3.10 -I/usr/include/python3.10  -Wno-unused-result -Wsign-compare -g      -fstack-protector-strong -Wformat -Werror=format-security  -DNDEBUG -g -fwrapv -O2 -Wall

LDFLAGS+= `python3.10-config --embed --ldflags`
CFLAGS+= `python3.10-config --embed --cflags`


openssl1_harness : $(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a 
	$(FUZZERCXX) ./build/$(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a -ldl $(LDFLAGS) -o ./build/$@

%.o : %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openssl1_harness
	
