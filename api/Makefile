# Makefile for Wazuh API
# Copyright (C) 2015-2019, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | install]

OSSEC_GROUP       = ossec
PREFIX            = /var/ossec

RM_FILE      = rm -f
INSTALL_DIR  = install -o root -g ${OSSEC_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${OSSEC_GROUP} -m 0640


.PHONY: all install

all: install

install:
	$(INSTALL_DIR) $(PREFIX)/api/api
	$(INSTALL_DIR) $(PREFIX)/api/api/controllers
	$(INSTALL_DIR) $(PREFIX)/api/api/models
	$(INSTALL_DIR) $(PREFIX)/api/api/spec
	$(INSTALL_DIR) $(PREFIX)/api/configuration

	$(INSTALL_FILE) api/*.py ${PREFIX}/api/api
	$(INSTALL_FILE) api/controllers/*.py ${PREFIX}/api/api/controllers
	$(INSTALL_FILE) api/models/*.py ${PREFIX}/api/api/models
	$(INSTALL_FILE) api/spec/*.yaml ${PREFIX}/api/api/spec
	$(INSTALL_FILE) api/configuration/template-api.yml ${PREFIX}/api/configuration

#	Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) $(script) $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)
