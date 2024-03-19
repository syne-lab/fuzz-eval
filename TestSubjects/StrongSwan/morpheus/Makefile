_dummy := $(shell mkdir -p build)

all : strongswan_harness

STRONGSWAN_HOME=./strongswan-5.9.2
SWLIBS=$(STRONGSWAN_HOME)/src/libstrongswan/.libs

GMP_LIBS=./gmp-6.1.2/build/lib

CFLAGS+= -include $(STRONGSWAN_HOME)/config.h
CFLAGS+= -I$(STRONGSWAN_HOME)/src/libstrongswan/


OBJ=strongswan_harness.o

strongswan_harness : $(OBJ) $(SWLIBS)/libstrongswan.a $(GMP_LIBS)/libgmp.a
	$(FUZZERCC) ./build/$(OBJ) $(SWLIBS)/libstrongswan.a $(GMP_LIBS)/libgmp.a $(LDFLAGS) -lpthread -ldl -o ./build/$@
	
%.o : %.c
	$(CC) -c $(CFLAGS) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openswan_harness
