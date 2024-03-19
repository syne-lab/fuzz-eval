# Cyiu: based on the Makefile of the axTLS samples

all : axtls_harness

AXTLS_HOME=..
LIBS=$(AXTLS_HOME)/$(STAGE)

include $(AXTLS_HOME)/config/.config
include $(AXTLS_HOME)/config/makefile.conf

OBJ=axtls_harness.o

LDFLAGS+=`python3-config --embed --ldflags`
CFLAGS+=`python3-config --embed --cflags`
CFLAGS+=-fsanitize=fuzzer
LDFLAGS+=-fsanitize=fuzzer



axtls_harness: $(OBJ) $(LIBS)/libaxtls.a
	$(FUZZERCC) -o $@ $(OBJ) $(LIBS)/libaxtls.a $(LDFLAGS) 
ifdef CONFIG_STRIP_UNWANTED_SECTIONS
	$(STRIP) --remove-section=.comment $@
endif   # use strip

include $(AXTLS_HOME)/config/makefile.post

clean::
	-@rm -f $(AXTLS_HOME)/$(STAGE)/axtls_harness*

#/Fuzzers/LibFuzzer/Test_axTLS/axTLS-2.1.5/test-harness/axtls_harness /Fuzzers/LibFuzzer/Test_axTLS/TEST -detect_leaks=0 -max_len=500 -seed=345 -timeout=4000 -rss_limit_mb=4096 -max_total_time=120 -fork=1 -ignore_crashes=1 --6001