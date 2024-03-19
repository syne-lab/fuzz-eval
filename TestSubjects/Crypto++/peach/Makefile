# Cyiu: based on the Makefile of the axTLS samples

_dummy := $(shell mkdir -p build)

all : cryptopp_harness

CRYPTOPPDIR = cryptopp850

.PHONY: clean

# test_pkcs1:
# 	g++ $@.cxx -I$(CRYPTOPPDIR) -L$(CRYPTOPPDIR) -lcryptopp -o $@

# clean:
# 	rm -rf test_pkcs1


OBJ=cryptopp_harness.o

LDFLAGS=`python3.10-config --embed --ldflags`
CFLAGS=`python3.10-config --embed --cflags`



cryptopp_harness : $(OBJ)
	$(FUZZERCXX) ./build/$(OBJ) -L$(CRYPTOPPDIR) -lcryptopp $(LDFLAGS) -o ./build/$@

%.o : %.cpp
	$(CXX) -c $(CFLAGS) -I$(CRYPTOPPDIR) $< -o ./build/$@

clean:
	rm -f ./build/${OBJ} ./build/cryptopp_harness
