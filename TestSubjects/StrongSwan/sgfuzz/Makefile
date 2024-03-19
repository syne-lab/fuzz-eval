_dummy := $(shell mkdir -p build)

all : strongswan_harness

STRONGSWAN_HOME=./strongswan-5.9.2
SWLIBS=$(STRONGSWAN_HOME)/src/libstrongswan/.libs

GMP_LIBS=./gmp-6.1.2/build/lib

CFLAGS+= -include $(STRONGSWAN_HOME)/config.h
CFLAGS+= -I$(STRONGSWAN_HOME)/src/libstrongswan/


LDFLAGS+=-lpython3.10 -lcrypt -lpthread -ldl  -lutil -lm -lm
CFLAGS+=-I/usr/local/include/python3.10 -I/usr/local/include/python3.10  -Wno-unused-result -Wsign-compare -g      -fstack-protector-strong -Wformat -Werror=format-security  -DNDEBUG -g -fwrapv -O2 -Wall
OBJ=strongswan_harness.o

strongswan_harness : $(OBJ) $(SWLIBS)/libstrongswan.a $(GMP_LIBS)/libgmp.a
	$(FUZZERCXX) -fsanitize=fuzzer-no-link ./build/$(OBJ) $(SWLIBS)/libstrongswan.a $(GMP_LIBS)/libgmp.a /SGFuzz/libsfuzzer.a $(LDFLAGS) -lpthread -ldl -o ./build/$@
	
%.o : %.c
	$(CC) -c -fsanitize=fuzzer-no-link $(CFLAGS) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openswan_harness
