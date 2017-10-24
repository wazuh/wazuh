# Makefile for Wazuh Framework
# Copyright 2017 Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

OSSEC_GROUP  = ossec
PREFIX       = /var/ossec

CC           = gcc
CFLAGS       = -pipe -O2
THREAD_FLAGS = -pthread -Wall
LFLAGS       = -O2
RM_FILE      = rm -f
INSTALL_DIR  = install -o root -g ${OSSEC_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${OSSEC_GROUP} -m 0640

SQLITE_DIR       = ../src/external/sqlite
TARGET           = libsqlite3.so.0 cluster_daemon

.PHONY: all build install examples clean

all: build

install: build
	$(INSTALL_DIR) $(PREFIX)/framework
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh
	$(INSTALL_DIR) $(PREFIX)/framework/lib

	$(INSTALL_EXEC) wazuh/*.py ${PREFIX}/framework/wazuh
	$(INSTALL_FILE) libsqlite3.so.0 ${PREFIX}/framework/lib
	$(INSTALL_EXEC) cluster_daemon ${PREFIX}/framework

#	Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) $(script) $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)

examples: install
	$(INSTALL_DIR) $(PREFIX)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${PREFIX}/framework/examples

build: $(TARGET)

libsqlite3.so.0: sqlite3.o
	$(CC) $(LFLAGS) -shared -o $@ $^

cluster_daemon: cluster_daemon.o sqlite3.o
	$(CC) $(THREAD_FLAGS) -o $@ $^ -ldl

sqlite3.o: $(SQLITE_DIR)/sqlite3.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $^

cluster_daemon.o: wazuh/cluster_daemon.c
	$(CC) $(CFLAGS) $(THREAD_FLAGS) -c $^ -o $@ -I $(SQLITE_DIR) -ldl

clean:
	$(RM_FILE) $(TARGET)
