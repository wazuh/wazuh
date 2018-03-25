# Makefile for Wazuh Framework
# Copyright 2017 Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

OSSEC_GROUP  = ossec
PREFIX       = /var/ossec

OPENSSL_DIR      = ../src/external/openssl
JSON_DIR         = ../src/external/cJSON

CC           = gcc
CFLAGS       = -pipe -Wall -Wextra
LDFLAGS      = -L$(JSON_DIR) -L$(OPENSSL_DIR) -Wl,-rpath,../lib
LIBS         = -lcjson -lssl -lcrypto -ldl -lm
THREAD_FLAGS = -pthread
RM_FILE      = rm -f
INSTALL_DIR  = install -o root -g ${OSSEC_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${OSSEC_GROUP} -m 0640

SQLITE_DIR       = ../src/external/sqlite
HEADERS_DIR      = ../src/headers
MD5_DIR          = ../src/os_crypto/md5

DEBUG_OP         = ../src/shared/debug_op.o
XML_LIB          = ../src/os_xml/os_xml.o
XML_ACCESS       = ../src/os_xml/os_xml_access.o
STRBREAK         = ../src/os_regex/os_regex_strbreak.o
REGEX_OP         = ../src/shared/regex_op.o
STRING_OP        = ../src/shared/string_op.o
FILE_OP          = ../src/shared/file_op.o
PRIVSEP_OP       = ../src/shared/privsep_op.o
HELP_O           = ../src/shared/help.o
ERROR_MSGS       = ../src/error_messages
QUEUE_OP         = ../src/shared/queue_op.o
HASH_OP          = ../src/shared/hash_op.o
MATH_OP          = ../src/shared/math_op.o
RANDOMBYTES      = ../src/shared/randombytes.o
MD5_OP           = ../src/os_crypto/md5/md5_op.o
VERSION_OP       = ../src/shared/version_op.o

DEBUG_OP_DEPS    = $(DEBUG_OP) $(JSON_LIB) $(XML_LIB) $(XML_ACCESS) $(STRBREAK) $(STRING_OP) $(FILE_OP) $(PRIVSEP_OP) $(REGEX_OP) $(HELP_O) $(VERSION_OP)
HASH_OP_DEPS     = $(HASH_OP) $(MATH_OP) $(RANDOMBYTES)
MD5_DEPS         = $(MD5_OP)

BUILD_TARGET     = libsqlite3.so.0

ifeq (${uname_S},Linux)
BUILD_TARGET     += wazuh-clusterd-internal
endif

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

	$(INSTALL_FILE) wazuh/*.py ${PREFIX}/framework/wazuh
	$(INSTALL_FILE) wazuh/*.json ${PREFIX}/framework/wazuh
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh/cluster
	$(INSTALL_FILE) wazuh/cluster/*.py ${PREFIX}/framework/wazuh/cluster
	$(INSTALL_FILE) libsqlite3.so.0 ${PREFIX}/framework/lib/
ifeq (${uname_S},Linux)
	$(INSTALL_EXEC) wazuh-clusterd-internal ${PREFIX}/bin
endif

#	Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) $(script) $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)

examples: install
	$(INSTALL_DIR) $(PREFIX)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${PREFIX}/framework/examples

build: $(BUILD_TARGET)

libsqlite3.so.0: $(SQLITE_DIR)/sqlite3.o
	$(CC) $(LFLAGS) -shared -o $@ $^

ifeq (${uname_S},Linux)
wazuh-clusterd-internal: wazuh-clusterd-internal.o $(SQLITE_DIR)/sqlite3.o $(DEBUG_OP_DEPS) $(HASH_OP_DEPS) $(QUEUE_OP) $(MD5_DEPS)
	$(CC) $(THREAD_FLAGS) -DDEFAULTDIR=\"${PREFIX}\" $(LDFLAGS) $^ -o $@ $(LIBS)
endif

ifeq (${uname_S},Linux)
wazuh-clusterd-internal.o: wazuh/wazuh-clusterd-internal.c
	$(CC) $(CFLAGS) $(THREAD_FLAGS) -DDEFAULTDIR=\"${PREFIX}\" -c $^ -o $@ -I $(SQLITE_DIR) -I $(JSON_DIR) -I $(HEADERS_DIR) -I $(ERROR_MSGS) -I $(MD5_DIR) -I $(OPENSSL_DIR)/include -ldl
endif

clean:
	$(RM_FILE) $(BUILD_TARGET) *.o *.so.0
