# written by Sze Yiu
# adapted by S Mahmudul Hasan
# based on matrixssl's app/dtls
_dummy := $(shell mkdir -p build)
all : matrixssl_harness
MATRIXSSL_ROOT:=./matrixssl-4-3-0-open


PKCS1_SRC:=matrixssl_harness.c

PKCS1_EXE:=matrixssl_harness$(E)

SRC:=$(PKCS1_SRC)

include $(MATRIXSSL_ROOT)/common.mk

# Linked files
STATIC:=\
	$(MATRIXSSL_ROOT)/matrixssl/libssl_s.a \
	$(MATRIXSSL_ROOT)/crypto/libcrypt_s.a \
	$(MATRIXSSL_ROOT)/core/libcore_s.a

CIPHER_OPTION=ID_RSA # The default cipher option
CFLAGS+=-D$(CIPHER_OPTION)

# # Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

OBJ=matrixssl_harness.o

matrixssl_harness : $(OBJ) $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h) $(STATIC)
	$(FUZZERCC) ./build/$(OBJ) $(STATIC) $(LDFLAGS) -o ./build/$@

%.o : %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/matrixssl_harness
