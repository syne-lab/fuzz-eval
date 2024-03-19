# written by Sze Yiu
# based on matrixssl's app/dtls
_dummy := $(shell mkdir -p build)

MATRIXSSL_ROOT:=./matrixssl-4-3-0-open


FLAGS=-fsanitize=fuzzer
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

LDFLAGS+=-lpython3.10 -lcrypt -lpthread -ldl  -lutil -lm -lm -fsanitize=fuzzer
CFLAGS+=-I/usr/local/include/python3.10 -I/usr/local/include/python3.10  -Wno-unused-result -Wsign-compare -g      -fstack-protector-strong -Wformat -Werror=format-security  -DNDEBUG -g -fwrapv -O2 -Wall -fsanitize=fuzzer


all: compile

compile: $(OBJS) $(PKCS1_EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(PKCS1_EXE): ./build/$(PKCS1_SRC:.c=.o) $(STATIC)
	$(FUZZERCC) -o ./build/$@ $^ $(LDFLAGS)

clean:
	rm -f ./build/$(PKCS1_EXE) ./build/$(OBJS)

