# Makefile for Wazuh APIs
# Copyright (C) 2015, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | install | service ]

WAZUH_GROUP       = wazuh
INSTALLDIR       ?= /var/ossec

MV_FILE        = mv -f
INSTALL_DIR    = install -o root -g ${WAZUH_GROUP} -m 0750 -d
INSTALL_EXEC   = install -o root -g ${WAZUH_GROUP} -m 0750
INSTALL_FILE   = install -o root -g ${WAZUH_GROUP} -m 0640


.PHONY: all install

all: install

install:
    # Copy files and create folders
	$(INSTALL_DIR) $(INSTALLDIR)

	$(INSTALL_DIR) $(INSTALLDIR)/apis/scripts
	$(INSTALL_FILE) scripts/wazuh_comms_apid.py ${INSTALLDIR}/apis/scripts

    # Install scripts/%.py on $(INSTALLDIR)/bin/%
	$(foreach script,$(wildcard scripts/*.py),$(INSTALL_EXEC) ../wrappers/generic_wrapper.sh $(patsubst scripts/%.py,$(INSTALLDIR)/bin/%,$(script));)
	
	$(MV_FILE) $(INSTALLDIR)/bin/wazuh_comms_apid $(INSTALLDIR)/bin/wazuh-comms-apid

