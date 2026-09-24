# tsmapi — C bridge from vgwtaped to the IBM Storage Protect 8.1 Data API.
#
#   make            builds ./tsmapi linking libApiTSM64.so
#   make test       builds + runs the protocol self-test (no server needed)
#   make install    installs alongside other VGWTaped tools  (DESTDIR=/usr/local default)
#
# The Go build (versitygw) stays pure-Go; only this helper needs the SDK.
TSM_SDK   ?= /opt/tivoli/tsm/client/api/bin64
# libApiTSM64.so depends on the IBM GSK8 crypto libs; give the linker their
# location so the runtime linker finds them too.
GSK8_LIB  ?= /usr/local/ibm/gsk8_64/lib64
CC        ?= cc
CFLAGS    ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CPPFLAGS += -I$(TSM_SDK) -I$(TSM_SDK)/sample
LDFLAGS  += -L$(TSM_SDK) -Wl,-rpath,$(TSM_SDK) -L$(GSK8_LIB) -Wl,-rpath,$(GSK8_LIB)
# Link the GSK8 crypto libs directly so they are our own DT_NEEDED entries
# resolved via rpath above (libApiTSM64.so's transitive gsk8 deps would
# otherwise require LD_LIBRARY_PATH at runtime). --no-as-needed is required:
# none of our code references gsk8 symbols directly.
LIBS     += -lApiTSM64 -Wl,--no-as-needed -lgsk8ssl_64 -lgsk8iccs_64 -lgsk8km_64

all: tsmapi

tsmapi: tsmapi.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

test: tsmapi
	./test/run_protocol_test.sh

install: tsmapi
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 tsmapi $(DESTDIR)/usr/local/bin/tsmapi

clean:
	rm -f tsmapi

.PHONY: all test install clean
