# Makefile for Wazuh Framework
# Copyright (C) 2015, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

WAZUH_USER        = wazuh-server
WAZUH_GROUP       = wazuh-server
WAZUH_SERVER	  = wazuh-server

SHARE_INSTALLDIR       ?= /usr/share/${WAZUH_SERVER}
LOG_INSTALLDIR         ?= /var/log/${WAZUH_SERVER}
LIB_INSTALLDIR         ?= /var/lib/${WAZUH_SERVER}
ETC_INSTALLDIR         ?= /etc/${WAZUH_SERVER}
BIN_INSTALLDIR         ?= ${SHARE_INSTALLDIR}/bin

CC           = gcc
CFLAGS       = -pipe -Wall -Wextra
THREAD_FLAGS = -pthread
MV_FILE      = mv -f
RM_FILE      = rm -f
INSTALL_REGULAR_DIR  = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0750  -d
INSTALL_RESTRICTED_DIR  = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0500  -d
INSTALL_EXEC = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0750
INSTALL_FILE = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0640

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
	# SHARE
	$(INSTALL_REGULAR_DIR) $(BIN_INSTALLDIR)
	$(INSTALL_REGULAR_DIR) $(SHARE_INSTALLDIR)/framework
	$(INSTALL_REGULAR_DIR) $(SHARE_INSTALLDIR)/framework/scripts
	$(INSTALL_REGULAR_DIR) $(SHARE_INSTALLDIR)/framework/wazuh
	$(INSTALL_REGULAR_DIR) $(SHARE_INSTALLDIR)/framework/wazuh/core/cluster
	$(INSTALL_REGULAR_DIR) $(SHARE_INSTALLDIR)/framework/wazuh/core/cluster/dapi
	$(INSTALL_REGULAR_DIR) $(SHARE_INSTALLDIR)/framework/wazuh/core/cluster/hap_helper

	# LOGS
	$(INSTALL_REGULAR_DIR) $(LOG_INSTALLDIR)

	# ETC
	$(INSTALL_REGULAR_DIR) $(ETC_INSTALLDIR)
	$(INSTALL_REGULAR_DIR) $(ETC_INSTALLDIR)/cluster
	$(INSTALL_RESTRICTED_DIR) $(ETC_INSTALLDIR)/certs
	$(INSTALL_REGULAR_DIR) $(ETC_INSTALLDIR)/groups

	# SHARE
	$(INSTALL_EXEC) scripts/wazuh_server.py ${SHARE_INSTALLDIR}/framework/scripts/wazuh-server.py
	$(INSTALL_FILE) wazuh/*.py ${SHARE_INSTALLDIR}/framework/wazuh
	$(INSTALL_FILE) wazuh/core/cluster/*.py ${SHARE_INSTALLDIR}/framework/wazuh/core/cluster
	$(INSTALL_FILE) wazuh/core/cluster/dapi/*.py ${SHARE_INSTALLDIR}/framework/wazuh/core/cluster/dapi
	$(INSTALL_FILE) wazuh/core/cluster/hap_helper/*.py ${SHARE_INSTALLDIR}/framework/wazuh/core/cluster/hap_helper

	# ETC
	$(INSTALL_FILE) ../etc/wazuh-server.yml ${ETC_INSTALLDIR}


	# BIN
#	Install scripts/%.py on $(INSTALLDIR)/bin/%
	$(foreach script,$(wildcard scripts/*.py),$(INSTALL_EXEC) wrappers/generic_wrapper.sh $(patsubst scripts/%.py,${BIN_INSTALLDIR}/%,$(script));)
#   Provisional name change for wazuh-logtest and wazuh-clusterd
	$(MV_FILE) ${BIN_INSTALLDIR}/wazuh_server ${BIN_INSTALLDIR}/wazuh-server
	$(RM_FILE) ${BIN_INSTALLDIR}/__init__

examples: install
	$(INSTALL_REGULAR_DIR) $(INSTALLDIR)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${INSTALLDIR}/framework/examples

clean:
	$(RM_FILE) $(BUILD_TARGET) *.o *.so.0
