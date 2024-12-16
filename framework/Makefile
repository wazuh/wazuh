# Makefile for Wazuh Framework
# Copyright (C) 2015, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

WAZUH_USER        = wazuh
WAZUH_GROUP       = wazuh
WAZUH_SERVER	  = wazuh-server

SHARE_INSTALLDIR       ?= /usr/share/${WAZUH_SERVER}
LOG_INSTALLDIR         ?= /var/log/${WAZUH_SERVER}
LIB_INSTALLDIR         ?= /var/lib/${WAZUH_SERVER}
ETC_INSTALLDIR         ?= /etc/${WAZUH_SERVER}
RUN_INSTALLDIR         ?= /run/${WAZUH_SERVER}
BIN_INSTALLDIR         ?= ${SHARE_INSTALLDIR}/bin

CC           = gcc
CFLAGS       = -pipe -Wall -Wextra
THREAD_FLAGS = -pthread
MV_FILE      = mv -f
RM_FILE      = rm -f
INSTALL_DIR  = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0750  -d
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
	$(INSTALL_DIR) $(BIN_INSTALLDIR)
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/framework
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/framework/scripts
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/framework/wazuh
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/framework/wazuh/core/cluster
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/framework/wazuh/core/cluster/dapi
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/framework/wazuh/core/cluster/hap_helper

	# LOGS
	$(INSTALL_DIR) $(LOG_INSTALLDIR)

	# ETC
	$(INSTALL_DIR) $(ETC_INSTALLDIR)
	$(INSTALL_DIR) $(ETC_INSTALLDIR)/cluster
	$(INSTALL_DIR) $(ETC_INSTALLDIR)/certs
	$(INSTALL_DIR) $(ETC_INSTALLDIR)/groups

	# RUN
	$(INSTALL_DIR) $(RUN_INSTALLDIR)
	$(INSTALL_DIR) $(RUN_INSTALLDIR)/cluster
	$(INSTALL_DIR) $(RUN_INSTALLDIR)/socket

	# SHARE
	$(INSTALL_FILE) scripts/*.py ${SHARE_INSTALLDIR}/framework/scripts
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
	$(INSTALL_DIR) $(INSTALLDIR)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${INSTALLDIR}/framework/examples

clean:
	$(RM_FILE) $(BUILD_TARGET) *.o *.so.0
