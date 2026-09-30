# Standalone contract test for the <container_security><syscheck> parser.
#
# Companion to ../container_security/, which covers the modulesd half of the same
# section. Split rather than merged because the two halves need different sources:
# this one pulls in syscheck-config.c and the real OSList, regex and string
# helpers, whose definitions collide with that harness's stubs.
#
#   make check

SRC_ROOT := ../../..
EXTERNAL ?= $(SRC_ROOT)/external

INCLUDES := \
  -I$(SRC_ROOT) \
  -I$(SRC_ROOT)/headers \
  -I$(SRC_ROOT)/shared/include \
  -I$(SRC_ROOT)/shared/include/error_messages \
  -I$(SRC_ROOT)/shared/os_regex \
  -I$(SRC_ROOT)/shared/os_xml \
  -I$(SRC_ROOT)/shared/os_crypto/sha1 \
  -I$(SRC_ROOT)/shared/os_crypto/md5 \
  -I$(SRC_ROOT)/shared/os_crypto/sha256 \
  -I$(SRC_ROOT)/shared/os_crypto/md5_sha1_sha256 \
  -I$(SRC_ROOT)/shared/os_net \
  -I$(SRC_ROOT)/config/include \
  -I$(SRC_ROOT)/syscheckd/include \
  -I$(SRC_ROOT)/wazuh_modules/include \
  -I$(SRC_ROOT)/wazuh_modules/src \
  -I$(SRC_ROOT)/wazuh_modules/src/agent_upgrade \
  -I$(SRC_ROOT)/shared_modules/common \
  -I$(SRC_ROOT)/shared_modules/dbsync/include \
  -I$(EXTERNAL)/cJSON \
  -I$(EXTERNAL)/libpcre2/include \
  -I$(EXTERNAL)/sqlite \
  -I$(EXTERNAL)/bzip2 \
  -I$(EXTERNAL)/zlib \
  -I$(EXTERNAL)/openssl/include \
  -I$(EXTERNAL)/curl/include/curl \
  -I$(EXTERNAL)/libyaml/include \
  -I$(EXTERNAL)/procps

CFLAGS := -std=gnu99 -g -O0 -Wall -D__linux__ -DCLIENT -DARGV0='"wazuh-syscheckd"' $(INCLUDES)

SOURCES := \
  container_security_syscheck_test.c \
  stubs.c \
  $(SRC_ROOT)/config/src/container-security-syscheck.c \
  $(SRC_ROOT)/config/src/syscheck-config.c \
  $(SRC_ROOT)/shared/src/list_op.c \
  $(SRC_ROOT)/shared/src/string_op.c \
  $(EXTERNAL)/cJSON/cJSON.c \
  $(SRC_ROOT)/shared/os_regex/os_regex_strbreak.c \
  $(SRC_ROOT)/shared/os_regex/os_regex_str.c \
  $(SRC_ROOT)/shared/os_xml/os_xml.c \
  $(SRC_ROOT)/shared/os_xml/os_xml_access.c \
  $(SRC_ROOT)/shared/os_xml/os_xml_node_access.c

TARGET := container_security_syscheck_test

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

.PHONY: check clean

check: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
