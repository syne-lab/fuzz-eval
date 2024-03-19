_dummy := $(shell mkdir -p build)

OPENSWANSRCDIR=./Openswan-3.0.0
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE}
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include

EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}    ${LIBGMP} ${CRYPTOLIBS} ${LDFLAGS}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_crypto.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_rsa.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/keymgmt.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/signatures.o
EXTRAOBJS+=${OBJDIRTOP}/lib/libpluto/libpluto.a

all : openswan_harness

OBJ=openswan_harness.o


CFLAGS+= -I/usr/local/include/${USEDPYTHON} -I/usr/local/include/${USEDPYTHON}  -Wno-unused-result -Wsign-compare  -DNDEBUG -g -fwrapv -O3 -Wall
LDFLAGS+= -l${USEDPYTHON} -lcrypt -lpthread -ldl  -lutil -lm -lm 

openswan_harness : $(OBJ) $(EXTRAOBJS) $(EXTRALIBS) $(EXTRALIBS)
	$(FUZZERCC) ./build/$(OBJ) $(EXTRAOBJS) $(EXTRALIBS) $(EXTRALIBS) $(LDFLAGS) -o ./build/$@
	
%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRAFLAGS) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/openswan_harness
