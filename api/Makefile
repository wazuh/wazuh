# Makefile for Wazuh API
# Copyright (C) 2015-2019, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | install]

OSSEC_GROUP       = ossec
PREFIX            = /var/ossec

RM_FILE        = rm -f
INSTALL_DIR    = install -o root -g ${OSSEC_GROUP} -m 0750 -d
INSTALL_RW_DIR = install -o root -g ${OSSEC_GROUP} -m 0770 -d
INSTALL_EXEC   = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE   = install -o root -g ${OSSEC_GROUP} -m 0640
PYTHON_BIN     = $(PREFIX)/framework/python/bin/python3


.PHONY: all install

all: install

install:
	$(INSTALL_DIR) $(PREFIX)/api/configuration
	$(INSTALL_RW_DIR) $(PREFIX)/api/configuration/security

	$(INSTALL_FILE) api/configuration/template-api.yaml ${PREFIX}/api/configuration
	$(INSTALL_FILE) api/configuration/uwsgi.yaml ${PREFIX}/api/configuration

	$(INSTALL_DIR) $(PREFIX)/api/scripts
	$(INSTALL_FILE) scripts/*.py ${PREFIX}/api/scripts

    # Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) wrappers/generic_wrapper.sh $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)