# SPIKE #37738 PoC — self-contained. NOT part of the agent build; never linked
# into a daemon. Builds a standalone C client over libcurl + libcrypto (CMAC).
#
# Local (macOS/Homebrew) uses system libcurl + openssl@3. In-tree production
# would instead link src/external/curl + src/external/openssl and route symbols
# through libwazuhext, exactly like the C `wurl` client does today (deep dive 3).

CC      ?= cc
BIN      = hc_poc
BIN_MT   = hc_poc_mt
CORE     = src/hc_client.c src/hc_cmac.c
SRC      = $(CORE) src/main.c
SRC_MT   = $(CORE) src/main_mt.c
CFLAGS  += -std=c11 -Wall -Wextra -Iinclude -Isrc -pthread

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
  CURL_PREFIX    ?= $(shell brew --prefix curl 2>/dev/null)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include -I$(CURL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib -L$(CURL_PREFIX)/lib
endif
LDLIBS  += -lcurl -lcrypto

all: $(BIN) $(BIN_MT)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS) $(LDLIBS)

$(BIN_MT): $(SRC_MT)
	$(CC) $(CFLAGS) $(SRC_MT) -o $(BIN_MT) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(BIN) $(BIN_MT)

.PHONY: all clean
