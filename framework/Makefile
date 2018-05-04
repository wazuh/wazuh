# Makefile for Wazuh Framework
# Copyright 2017 Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

OSSEC_GROUP  = ossec
PREFIX       = /var/ossec

CC           = gcc
CFLAGS       = -pipe -Wall -Wextra
THREAD_FLAGS = -pthread
RM_FILE      = rm -f
INSTALL_DIR  = install -o root -g ${OSSEC_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${OSSEC_GROUP} -m 0640

SQLITE_DIR       = ../src/external/sqlite

BUILD_TARGET     = libsqlite3.so.0


ifdef DEBUG
	CFLAGS+=-g -I ../src
	LFLAGS+=-Wl,-g
else
	CFLAGS+=-O2 -I ../src
	LFLAGS+=-Wl,-O2
endif

.PHONY: all build install examples clean

all: build

install:
	$(INSTALL_DIR) $(PREFIX)/framework
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh
	$(INSTALL_DIR) $(PREFIX)/framework/lib
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh/cluster

	$(INSTALL_FILE) wazuh/*.py ${PREFIX}/framework/wazuh
	$(INSTALL_FILE) wazuh/cluster/*.json ${PREFIX}/framework/wazuh/cluster
	$(INSTALL_FILE) wazuh/cluster/*.py ${PREFIX}/framework/wazuh/cluster
	$(INSTALL_FILE) libsqlite3.so.0 ${PREFIX}/framework/lib/

#	Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) $(script) $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)

examples: install
	$(INSTALL_DIR) $(PREFIX)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${PREFIX}/framework/examples

build: $(BUILD_TARGET)

libsqlite3.so.0: $(SQLITE_DIR)/sqlite3.o
	$(CC) $(LFLAGS) -shared -o $@ $^


clean:
	$(RM_FILE) $(BUILD_TARGET) *.o *.so.0
