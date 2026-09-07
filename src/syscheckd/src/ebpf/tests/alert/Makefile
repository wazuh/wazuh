# Container FIM stateless-alert test (#37532 WP2).
#
# Standalone (not wired into the CMake project) for the same reason as
# tests/txn/: it must be runnable wherever the tree builds, and `TEST=yes`
# cannot currently configure in every environment — see 09's environment notes
# on CMake 4.x versus the vendored googletest.
#
#   make check   -> builds and runs it
#   make clean
#
# Needs src/build/lib, i.e. `make build TARGET=agent` must have run first.
# Writes nothing to disk and opens no socket: send_syscheck_msg() is stubbed in
# the test, so the alerts are captured rather than queued.

SRC_ROOT ?= ../../../../..
LIB_DIR  ?= $(SRC_ROOT)/build/lib

CC       ?= cc
CXX      ?= c++
CFLAGS   ?= -std=gnu11 -O1 -Wall -Wextra

INCLUDES := \
  -I../../include \
  -I$(SRC_ROOT)/syscheckd/include \
  -I$(SRC_ROOT)/syscheckd/src/file \
  -I$(SRC_ROOT)/syscheckd/src/db/include \
  -I$(SRC_ROOT)/shared/include \
  -I$(SRC_ROOT)/shared/include/error_messages \
  -I$(SRC_ROOT)/shared/os_crypto/md5_sha1_sha256 \
  -I$(SRC_ROOT)/shared/os_crypto/md5 \
  -I$(SRC_ROOT)/shared/os_crypto/sha1 \
  -I$(SRC_ROOT)/shared/os_crypto/sha256 \
  -I$(SRC_ROOT)/shared/os_regex \
  -I$(SRC_ROOT)/shared/os_xml \
  -I$(SRC_ROOT)/shared/os_net \
  -I$(SRC_ROOT)/shared_modules/common \
  -I$(SRC_ROOT)/shared_modules/dbsync/include \
  -I$(SRC_ROOT)/shared_modules/sync_protocol/include \
  -I$(SRC_ROOT)/config/include \
  -I$(SRC_ROOT)/wazuh_modules/container_baseline/include \
  -I$(SRC_ROOT)/external/cJSON \
  -I$(SRC_ROOT)/external/libpcre2/include \
  -I$(SRC_ROOT)/external/sqlite \
  -I$(SRC_ROOT)/external/curl/include \
  -I$(SRC_ROOT)/external/curl/include/curl \
  -I$(SRC_ROOT)/external/libyaml/include \
  -I$(SRC_ROOT)/external/bzip2 \
  -I$(SRC_ROOT)

# The bridge is compiled in rather than taken from libfimebpf.so, because the
# .so also carries the drain, rt_engine and the container_baseline client — none
# of which this test exercises, all of which would need stubbing.
BRIDGE := ../../src/container_baseline_fim_bridge.c

# events.o (fim_attributes_json / fim_calculate_dbsync_difference) comes out of
# libsyscheckd_lib.a. Deliberately the REAL implementations: a container alert
# whose shape drifts from a host FIM alert is exactly what this test exists to
# catch. Archive linking is per-object, so run_check.o — send_syscheck_msg(),
# validate_and_persist_fim_event(), check_max_fps() — is NOT pulled in, and the
# test's own stubs for those three stand.
LIBS := -lsyscheckd_lib -lwazuh -lwazuhext -lpthread -ldl

# Compiled as C, linked with the C++ driver: libsyscheckd_lib.a carries C++
# objects, so the link needs libstdc++.
container_fim_alert_test: container_fim_alert_test.c $(BRIDGE)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o container_fim_alert_test.o container_fim_alert_test.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o container_baseline_fim_bridge.o $(BRIDGE)
	$(CXX) -o $@ container_fim_alert_test.o container_baseline_fim_bridge.o \
	    -L$(LIB_DIR) $(LIBS) -Wl,-rpath,$(abspath $(LIB_DIR))

check: container_fim_alert_test
	./container_fim_alert_test

clean:
	rm -f container_fim_alert_test container_fim_alert_test.o container_baseline_fim_bridge.o

.PHONY: check clean
