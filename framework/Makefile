# Makefile for Wazuh Framework
# Copyright (C) 2015-2020, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

OSSEC_GROUP       = ossec
PREFIX            = /var/ossec
USE_FRAMEWORK_LIB = no

CC           = gcc
CFLAGS       = -pipe -Wall -Wextra
THREAD_FLAGS = -pthread
RM_FILE      = rm -f
INSTALL_DIR  = install -o root -g ${OSSEC_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${OSSEC_GROUP} -m 0640

ifdef DEBUG
	CFLAGS+=-g -I ../src
	LFLAGS+=-g
else
	CFLAGS+=-O2 -I ../src
	LFLAGS+=-O2
endif

.PHONY: all build install examples clean

all: build

install:
	$(INSTALL_DIR) $(PREFIX)/framework
	$(INSTALL_DIR) $(PREFIX)/framework/scripts
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh/core/cluster
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh/core/cluster/dapi

	$(INSTALL_FILE) scripts/*.py ${PREFIX}/framework/scripts
	$(INSTALL_FILE) wazuh/*.py ${PREFIX}/framework/wazuh
	$(INSTALL_FILE) wazuh/core/cluster/*.json ${PREFIX}/framework/wazuh/core/cluster
	$(INSTALL_FILE) wazuh/core/cluster/*.py ${PREFIX}/framework/wazuh/core/cluster
	$(INSTALL_FILE) wazuh/core/cluster/dapi/*.py ${PREFIX}/framework/wazuh/core/cluster/dapi

#	Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) wrappers/generic_wrapper.sh $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)

examples: install
	$(INSTALL_DIR) $(PREFIX)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${PREFIX}/framework/examples

clean:
	$(RM_FILE) $(BUILD_TARGET) *.o *.so.0
