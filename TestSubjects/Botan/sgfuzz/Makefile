
# test_pkcs1:
# 	g++ $@.cpp -I$(BOTANDIR)/include/botan-2 -L$(BOTANDIR)/lib -lbotan-2 -Wl,-rpath $(BOTANDIR)/lib -o $@

# clean:
# 	rm -rf test_pkcs1



# Cyiu: based on the Makefile of the axTLS samples

_dummy := $(shell mkdir -p build)

BOTANDIR=Botan-2.17.3


all : botan_harness


.PHONY: clean

OBJ=botan_harness.o

LDFLAGS=`python3.10-config --embed --ldflags`
CFLAGS=`python3.10-config --embed --cflags`
CFLAGS+= -fsanitize=fuzzer-no-link
LDFLAGS+= -fsanitize=fuzzer-no-link


botan_harness : $(OBJ)
	$(FUZZERCXX) ./build/$(OBJ) -L$(BOTANDIR)/lib -lbotan-2 -Wl,-rpath $(BOTANDIR)/lib /SGFuzz/libsfuzzer.a $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c -std=c++11 $(CFLAGS) -I$(BOTANDIR)/include/botan-2  $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/botan_harness
