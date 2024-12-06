# Makefile for Wazuh API
# Copyright (C) 2015, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | backup | install | restore | service ]

WAZUH_USER        = wazuh-server
WAZUH_GROUP       = wazuh-server
WAZUH_SERVER      = wazuh-server
SHARE_INSTALLDIR  ?= /usr/share/${WAZUH_SERVER}
ETC_INSTALLDIR    ?= /etc/${WAZUH_SERVER}
BIN_INSTALLDIR    ?= ${SHARE_INSTALLDIR}/bin


MV_FILE        = mv -f
RM_FILE        = rm -f
INSTALL_DIR    = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0750 -d
INSTALL_RW_DIR = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0770 -d
INSTALL_EXEC   = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0750
INSTALL_FILE   = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0640
INSTALL_CONFIG_FILE   = install -o ${WAZUH_USER} -g ${WAZUH_GROUP} -m 0660
PYTHON_BIN     = $(SHARE_INSTALLDIR)/framework/python/bin/python3


.PHONY: install

install:
    # Copy files and create folders
	# SHARE
	$(INSTALL_DIR) $(SHARE_INSTALLDIR)/api/scripts
	$(INSTALL_EXEC) scripts/wazuh_apid.py ${SHARE_INSTALLDIR}/api/scripts/wazuh-apid.py

    # Install scripts/%.py on $(INSTALLDIR)/bin/%
	$(foreach script,$(wildcard scripts/*.py),$(INSTALL_EXEC) wrappers/generic_wrapper.sh $(patsubst scripts/%.py,${BIN_INSTALLDIR}/%,$(script));)

	$(MV_FILE) ${BIN_INSTALLDIR}/wazuh_server_management_apid ${BIN_INSTALLDIR}/wazuh-server-management-apid
