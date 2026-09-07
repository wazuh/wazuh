# Scoped-transaction contract test for the container FIM consumers.
#
# Standalone (not wired into the CMake project) for the same reason as the eBPF
# Module's contract tests: it must be runnable wherever the tree builds, and
# `TEST=yes` cannot currently configure in every environment — see 09's
# environment notes on CMake 4.x versus the vendored googletest.
#
#   make check   -> builds and runs it
#   make clean
#
# Needs a built libfimdb.so and libwazuhext.so, i.e. `make build TARGET=agent`
# (or at least `make -j fimdb wazuhext` in src/build) must have run first.
# Writes nothing to disk: the database is FIM_DB_MEMORY.

SRC_ROOT ?= ../../../../..
LIB_DIR  ?= $(SRC_ROOT)/build/lib

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O1 -Wall -Wextra

# Mirrors what the CMake target for libfimdb's own consumers pulls in: db.h
# reaches syscheck.h, which reaches most of shared/ and several externals.
INCLUDES := \
  -I$(SRC_ROOT)/syscheckd/src/db/include \
  -I$(SRC_ROOT)/syscheckd/include \
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
  -I$(SRC_ROOT)/headers \
  -I$(SRC_ROOT)/external/cJSON \
  -I$(SRC_ROOT)/external/libpcre2/include \
  -I$(SRC_ROOT)/external/sqlite \
  -I$(SRC_ROOT)/external/curl/include \
  -I$(SRC_ROOT)/external/curl/include/curl \
  -I$(SRC_ROOT)/external/libyaml/include \
  -I$(SRC_ROOT)/external/bzip2 \
  -I$(SRC_ROOT)

fim_container_txn_test: fim_container_txn_test.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -L$(LIB_DIR) -lfimdb -lwazuhext -Wl,-rpath,$(abspath $(LIB_DIR))

check: fim_container_txn_test
	./fim_container_txn_test

clean:
	rm -f fim_container_txn_test

.PHONY: check clean
