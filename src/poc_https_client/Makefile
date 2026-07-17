# SPIKE #37738 PoC — self-contained. NOT part of the agent build; never linked
# into a daemon. Builds a standalone client over libcurl + libcrypto (CMAC):
# C++17 core (hcClientFacade.*, hcCmac.*) behind a C ABI (hc_client.cpp
# implementing include/hc_client.h), with plain-C drivers standing in for the
# C agentd caller — the same boundary shape as the manager's remoted_module.
#
# Local (macOS/Homebrew) uses system libcurl + openssl@3. In-tree production
# would instead link src/external/curl + src/external/openssl and route symbols
# through libwazuhext, exactly like the C `wurl` client does today (deep dive 3).

CC      ?= cc
CXX     ?= c++
BIN      = hc_poc
BIN_MT   = hc_poc_mt
OBJDIR   = .build

CORE_OBJS = $(OBJDIR)/hcCmac.o $(OBJDIR)/hcClientFacade.o $(OBJDIR)/hc_client.o
HDRS      = include/hc_client.h src/hcClientFacade.hpp src/hcCmac.hpp

CFLAGS   += -std=c11   -Wall -Wextra -Iinclude -Isrc -pthread $(EXTRA_FLAGS)
CXXFLAGS += -std=c++17 -Wall -Wextra -Iinclude -Isrc -pthread $(EXTRA_FLAGS)
LDFLAGS  += $(EXTRA_FLAGS)

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
  CURL_PREFIX    ?= $(shell brew --prefix curl 2>/dev/null)
  CFLAGS   += -I$(OPENSSL_PREFIX)/include -I$(CURL_PREFIX)/include
  CXXFLAGS += -I$(OPENSSL_PREFIX)/include -I$(CURL_PREFIX)/include
  LDFLAGS  += -L$(OPENSSL_PREFIX)/lib -L$(CURL_PREFIX)/lib
endif
LDLIBS  += -lcurl -lcrypto

all: $(BIN) $(BIN_MT)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.cpp $(HDRS) | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/%.o: src/%.c include/hc_client.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# link with $(CXX): the core is C++; the drivers are C (that is the point)
$(BIN): $(CORE_OBJS) $(OBJDIR)/main.o
	$(CXX) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN_MT): $(CORE_OBJS) $(OBJDIR)/main_mt.o
	$(CXX) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# ThreadSanitizer build of the threaded demo (validates the D5 model)
tsan:
	$(MAKE) OBJDIR=.build-tsan BIN=hc_poc_tsan BIN_MT=hc_poc_mt_tsan \
	        EXTRA_FLAGS="-fsanitize=thread -g" hc_poc_mt_tsan

clean:
	rm -rf $(BIN) $(BIN_MT) hc_poc_tsan hc_poc_mt_tsan $(OBJDIR) .build-tsan

.PHONY: all clean tsan
