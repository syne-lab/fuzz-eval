_dummy := $(shell mkdir -p build)

all : gnutls_harness

GNUTLS_HOME=./gnutls-3.6.15/build
INC=-I${GNUTLS_HOME}/include/

LIBS=$(GNUTLS_HOME)/lib/libgnutls.a ./nettle-3.7.2/libhogweed.a ./nettle-3.7.2/libnettle.a ./gmp-6.1.2/build/lib/libgmp.a /SGFuzz/libsfuzzer.a

LDFLAGS+=`python3.10-config --embed --ldflags`
CFLAGS+=`python3.10-config --embed --cflags`
CFLAGS+="-fsanitize=fuzzer-no-link"
LDFLAGS+="-fsanitize=fuzzer-no-link"



OBJ=gnutls_harness.o

gnutls_harness : $(OBJ) $(LIBS)
	$(FUZZERCXX) ./build/$(OBJ) $(LIBS) $(LDFLAGS) -o ./build/$@ 

%.o : %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/gnutls_harness
	