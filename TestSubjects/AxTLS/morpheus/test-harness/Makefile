# Cyiu: based on the Makefile of the axTLS samples

all : axtls_harness

AXTLS_HOME=..
LIBS=$(AXTLS_HOME)/$(STAGE)

include $(AXTLS_HOME)/config/.config
include $(AXTLS_HOME)/config/makefile.conf

OBJ=axtls_harness.o

axtls_harness: $(OBJ) $(LIBS)/libaxtls.a
	$(FUZZERCC) -o $@ $(OBJ) $(LIBS)/libaxtls.a $(LDFLAGS)
ifdef CONFIG_STRIP_UNWANTED_SECTIONS
	$(STRIP) --remove-section=.comment $@
endif   # use strip

include $(AXTLS_HOME)/config/makefile.post

clean::
	-@rm -f $(AXTLS_HOME)/$(STAGE)/axtls_harness*

