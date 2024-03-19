_dummy := $(shell mkdir -p build)
all : openssl1_harness

OPENSSL_HOME=./openssl-1.1.1k
INC=-I${OPENSSL_HOME}/include/

OBJ=openssl1_harness.o

LDFLAGS+=-lpython3.10 -lcrypt -lpthread -ldl  -lutil -lm -lm
CFLAGS+=-I/usr/local/include/python3.10 -I/usr/local/include/python3.10  -Wno-unused-result -Wsign-compare -g      -fstack-protector-strong -Wformat -Werror=format-security  -DNDEBUG -g -fwrapv -O2 -Wall
CFLAGS+=-fsanitize=fuzzer-no-link
LDFLAGS+=-fsanitize=fuzzer-no-link


openssl1_harness : $(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a 
	$(FUZZERCXX) ./build/$(OBJ) $(OPENSSL_HOME)/libssl.a $(OPENSSL_HOME)/libcrypto.a /SGFuzz/libsfuzzer.a $(LDFLAGS)  -ldl -o ./build/$@

%.o : %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openssl1_harness
	
