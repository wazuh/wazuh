# Standalone contract test for the <container_security> configuration parser.
# No CMake and no built libraries: it compiles the real parser and the real XML
# reader from source, against stubs for the logging the parser does.
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
  -I$(SRC_ROOT)/shared/os_crypto/blowfish \
  -I$(SRC_ROOT)/shared/os_crypto/aes \
  -I$(SRC_ROOT)/shared/os_crypto/hmac \
  -I$(SRC_ROOT)/shared/os_crypto/sha512 \
  -I$(SRC_ROOT)/shared/os_net \
  -I$(SRC_ROOT)/shared/os_zlib \
  -I$(SRC_ROOT)/config/include \
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

CFLAGS := -std=gnu99 -g -O0 -Wall -D__linux__ -DCLIENT -DARGV0='"wazuh-modulesd"' $(INCLUDES)

SOURCES := \
  container_security_config_test.c \
  stubs.c \
  $(SRC_ROOT)/config/src/wmodules-container-instances.c \
  $(SRC_ROOT)/shared/os_xml/os_xml.c \
  $(SRC_ROOT)/shared/os_xml/os_xml_access.c \
  $(SRC_ROOT)/shared/os_xml/os_xml_node_access.c

TARGET := container_security_config_test

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

check: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: check clean
