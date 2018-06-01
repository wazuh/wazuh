# Makefile for Wazuh Framework
# Copyright 2017 Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | install | examples ]

OSSEC_GROUP  = ossec
PREFIX       = /var/ossec

INSTALL_DIR  = install -o root -g ${OSSEC_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${OSSEC_GROUP} -m 0640

.PHONY: all install examples

all:

install:
	$(INSTALL_DIR) $(PREFIX)/framework
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh
	$(INSTALL_DIR) $(PREFIX)/framework/wazuh/cluster

	$(INSTALL_FILE) wazuh/*.py ${PREFIX}/framework/wazuh
	$(INSTALL_FILE) wazuh/cluster/*.json ${PREFIX}/framework/wazuh/cluster
	$(INSTALL_FILE) wazuh/cluster/*.py ${PREFIX}/framework/wazuh/cluster

#	Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) $(script) $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)

examples: install
	$(INSTALL_DIR) $(PREFIX)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${PREFIX}/framework/examples
