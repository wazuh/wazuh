# D17 root-classification test for the container rootfs walker (#37532 WP3).
#
# Standalone, like the eBPF consumers' suites, and for the same reason: it must
# be runnable wherever the tree builds, and `TEST=yes` cannot currently
# configure in every environment.
#
#   make check   -> builds and runs it
#   make clean
#
# Needs src/build/lib, i.e. `make build TARGET=agent` must have run first.
# Creates and removes a directory under /tmp; forks once. Runs as an ordinary
# user — the permission case skips itself under root, where nothing is
# unreadable.

SRC_ROOT ?= ../../../../..
LIB_DIR  ?= $(SRC_ROOT)/build/lib

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O1 -Wall -Wextra

INCLUDES := \
  -I../../include \
  -I$(SRC_ROOT)/wazuh_modules/container_baseline/include \
  -I$(SRC_ROOT)/shared_modules/container_instances_client/include \
  -I$(SRC_ROOT)/shared/include \
  -I$(SRC_ROOT)/shared_modules/common \
  -I$(SRC_ROOT)/external/nlohmann \
  -I$(SRC_ROOT)/external/cJSON \
  -I$(SRC_ROOT)/external/openssl/include

LIBS := -lCONTAINER_BASELINE_IMPL -lwazuhext -lcrypto -lpthread -ldl

# The archive is a prerequisite, not just a -l flag: it is STATIC, so a rebuilt
# libCONTAINER_BASELINE_IMPL.a changes nothing until this relinks. Without this
# line the test silently keeps testing the code it was first linked against —
# which is exactly what happened, and it made three mutations look survived.
walk_root_classification_test: walk_root_classification_test.cpp $(LIB_DIR)/libCONTAINER_BASELINE_IMPL.a
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -L$(LIB_DIR) $(LIBS) -Wl,-rpath,$(abspath $(LIB_DIR))

check: walk_root_classification_test
	./walk_root_classification_test

clean:
	rm -f walk_root_classification_test

.PHONY: check clean
