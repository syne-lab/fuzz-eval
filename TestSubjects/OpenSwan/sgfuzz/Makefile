_dummy := $(shell mkdir -p build)

OPENSWANSRCDIR=./Openswan-3.0.0
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE}
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include

EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}    ${LIBGMP} ${CRYPTOLIBS} ${LDFLAGS} /SGFuzz/libsfuzzer.a

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_crypto.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_rsa.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/keymgmt.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/signatures.o
EXTRAOBJS+=${OBJDIRTOP}/lib/libpluto/libpluto.a

all : openswan_harness

OBJ=openswan_harness.o

LDFLAGS+=-lpython3.10 -lcrypt -lpthread -ldl  -lutil -lm -lm
CFLAGS+=-I/usr/local/include/python3.10 -I/usr/local/include/python3.10  -Wno-unused-result -Wsign-compare -g      -fstack-protector-strong -Wformat -Werror=format-security  -DNDEBUG -g -fwrapv -O2 -Wall


openswan_harness : $(OBJ) $(EXTRAOBJS) $(EXTRALIBS) $(EXTRALIBS)
	$(FUZZERCXX) -fsanitize=fuzzer-no-link ./build/$(OBJ) $(EXTRAOBJS) $(EXTRALIBS) $(EXTRALIBS) $(LDFLAGS) -o ./build/$@
	
%.o : %.c
	$(CC) -c -fsanitize=fuzzer-no-link $(CFLAGS) $(EXTRAFLAGS) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openswan_harness
