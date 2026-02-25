# Copyright (C) 2015, Wazuh Inc.
#
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
uname_V := $(shell sh -c 'uname -v 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')

# Accept both "server" and "manager" as equivalent targets
ifeq (${TARGET},server)
override TARGET := manager
endif

ifeq (${TARGET}, winagent)
WAZUH_LIB_OUTPUT_PATH := win32/
STRIP_TOOL := i686-w64-mingw32-strip
libstdc++_path := $(shell sh -c 'i686-w64-mingw32-g++-posix --print-file-name=libstdc++-6.dll 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++-6.dll
libgcc_s_path := $(shell sh -c 'i686-w64-mingw32-g++-posix --print-file-name=libgcc_s_dw2-1.dll 2>/dev/null || echo not')
LIBGCC_S_NAME := libgcc_s_dw2-1.dll
else
libstdc++_path := $(shell sh -c 'g++ --print-file-name=libstdc++.so.6 2>/dev/null || echo not')
libgcc_s_path := $(shell sh -c 'g++ --print-file-name=libgcc_s.so.1 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++.so.6
LIBGCC_S_NAME := libgcc_s.so.1
STRIP_TOOL := strip
endif

ifeq (, $(filter ${libstdc++_path}, not ${LIBSTDCPP_NAME}))
ifeq (, $(filter ${libgcc_s_path}, not ${LIBGCC_S_NAME}))
CPPLIBDEPS := ${LIBSTDCPP_NAME} ${LIBGCC_S_NAME}
endif
endif

HAS_CHECKMODULE = $(shell command -v checkmodule > /dev/null && echo YES)
HAS_SEMODULE_PACKAGE = $(shell command -v semodule_package > /dev/null && echo YES)
CHECK_ARCHLINUX := $(shell sh -c 'grep "Arch Linux" /etc/os-release > /dev/null && echo YES || echo not')
CHECK_ALPINE := $(shell sh -c 'grep "Alpine Linux" /etc/os-release 2>&1 > /dev/null && echo YES || echo not')

ARCH_FLAGS =

ROUTE_PATH := $(shell pwd)
EXTERNAL_JSON=external/cJSON/
EXTERNAL_ZLIB=external/zlib/
EXTERNAL_SQLITE=external/sqlite/
EXTERNAL_OPENSSL=external/openssl/
EXTERNAL_LIBYAML=external/libyaml/
EXTERNAL_CURL=external/curl/
EXTERNAL_AUDIT=external/audit-userspace/
EXTERNAL_LIBFFI=external/libffi/
EXTERNAL_LIBPLIST=external/libplist/
EXTERNAL_CPYTHON=external/cpython/
EXTERNAL_MSGPACK=external/msgpack/
EXTERNAL_BZIP2=external/bzip2/
EXTERNAL_GOOGLE_TEST=external/googletest/
EXTERNAL_GOOGLE_BENCHMARK=external/benchmark/
EXTERNAL_ROCKSDB=external/rocksdb/
EXTERNAL_RE2=external/re2/
EXTERNAL_ABSEILCPP=external/abseil-cpp/
EXTERNAL_FLATBUFFERS=external/flatbuffers/
EXTERNAL_FMT=external/fmt/
EXTERNAL_SPDLOG=external/spdlog/
EXTERNAL_YAMLCPP=external/yaml-cpp/
EXTERNAL_PUGIXML=external/pugixml/
EXTERNAL_MAXMINDDB=external/libmaxminddb/
EXTERNAL_PROTOBUF=external/protobuf/
EXTERNAL_DATE=external/date/
EXTERNAL_SIMDJSON=external/simdjson/
EXTERNAL_LZMA=external/lzma/
EXTERNAL_LUA=external/lua/
EXTERNAL_LIBPCRE2=external/libpcre2/
EXTERNAL_SIMDJSON=external/simdjson/
ifneq (${TARGET},winagent)
EXTERNAL_PROCPS=external/procps/
EXTERNAL_LIBDB=external/libdb/build_unix/
EXTERNAL_PACMAN=external/pacman/
EXTERNAL_LIBARCHIVE=external/libarchive/
endif
EXTERNAL_JEMALLOC=external/jemalloc/
ifeq (${uname_S},Linux)
EXTERNAL_RPM=external/rpm/
EXTERNAL_POPT=external/popt/
EXTERNAL_LIBBPF=external/libbpf-bootstrap/
EXTERNAL_DBUS=external/dbus/
endif
# XXX Becareful NO EXTRA Spaces here
ifeq ($(TARGET),manager)
WAZUH_USER?=wazuh-manager
WAZUH_GROUP?=wazuh-manager
else
WAZUH_USER?=wazuh
WAZUH_GROUP?=wazuh
endif
SELINUX_MODULE=selinux/wazuh.mod
SELINUX_ENFORCEMENT=selinux/wazuh.te
SELINUX_POLICY=selinux/wazuh.pp
USE_INOTIFY=no
USE_BIG_ENDIAN=no
USE_AUDIT=no
DISABLE_JEMALLOC?=no
IMAGE_TRUST_CHECKS?=1
CA_NAME?=DigiCert Assured ID Root CA
HTTP_REQUEST_BRANCH?=1a98c1aa40df0fe82136d790043c2f9cbf1a24c4

ifeq (${TARGET},winagent)
CMAKE_OPTS=-DCMAKE_SYSTEM_NAME=Windows -DCMAKE_C_COMPILER=${MING_BASE}${CC} -DCMAKE_CXX_COMPILER=${MING_BASE}${CXX} -DEVENTCHANNEL_SUPPORT=ON
endif

ifneq (,$(filter ${TEST},YES yes y Y 1))
WAZUH_TEST=-DUNIT_TEST=ON
endif
ifneq (,$(filter ${TEST},YES yes y Y 1)$(filter $(ENGINE_TEST),YES yes y Y 1))
ifeq ($(TEST),)
  CMAKE_ENGINE_OPTS = -DWAZUH_ENGINE_TEST=ON
else
  $(warning TEST is defined; skipping CMake engine test option)
endif
endif
ifneq (,$(filter ${FSANITIZE},YES yes y Y 1))
CMAKE_OPTS+=-DFSANITIZE=ON
endif
ifneq (,$(filter ${DISABLE_JEMALLOC},YES yes y Y 1))
CMAKE_OPTS+=-DDISABLE_JEMALLOC=ON
endif
ifneq (,$(filter ${USE_BIG_ENDIAN},YES yes y Y 1))
CMAKE_OPTS+=-DOS_BIG_ENDIAN=ON
endif
CMAKE_OPTS+=-DCA_NAME='${CA_NAME}' -DIMAGE_TRUST_CHECKS=${IMAGE_TRUST_CHECKS}
ifneq (${TARGET},winagent)
ifneq (,$(filter ${USE_INOTIFY},YES auto yes y Y 1))
CMAKE_OPTS+=-DINOTIFY_ENABLED=ON
else ifeq (${uname_S},Linux)
CMAKE_OPTS+=-DINOTIFY_ENABLED=ON
endif
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
CMAKE_OPTS+=-DENABLE_AUDIT=ON
else ifeq (${uname_S},Linux)
CMAKE_OPTS+=-DENABLE_AUDIT=ON
endif
endif
ifneq (,$(filter ${DEBUG},YES yes y Y 1))
WAZUH_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
endif

ifeq (${COVERITY}, YES)
	export COVERITY_UNSUPPORTED_COMPILER_INVOCATION=1
endif

ifneq ($(HAS_CHECKMODULE),)
ifneq ($(HAS_SEMODULE_PACKAGE),)
USE_SELINUX=yes
else
USE_SELINUX=no
endif
else
USE_SELINUX=no
endif

ifneq (${TARGET},winagent)
ifeq (${uname_S},Linux)
		PRECOMPILED_OS:=linux
		CC=gcc
else
ifeq (${uname_S},Darwin)
	PRECOMPILED_OS:=darwin
else
ifeq (${uname_S},FreeBSD)
		PRECOMPILED_OS:=freebsd
else
ifeq (${uname_S},NetBSD)
		PRECOMPILED_OS:=netbsd
else
ifeq (${uname_S},OpenBSD)
		PRECOMPILED_OS:=openbsd
else
	    # Unknow platform
endif # OpenBSD
endif # NetBSD
endif # FreeBSD
endif # Darwin
endif # Linux
else
		PRECOMPILED_OS:=windows
endif # winagent

# Check if symbol table should be included in release
ifeq (${uname_S},Linux)
	SYMBOLS_IN_RELEASE = YES
else ifeq (${uname_S},Darwin)
	SYMBOLS_IN_RELEASE = YES
else ifeq (${TARGET},winagent)
	SYMBOLS_IN_RELEASE = YES
endif

ifneq (,$(SYMBOLS_IN_RELEASE))
	CMAKE_OPTS+=-DCMAKE_SYMBOLS_IN_RELEASE=ON
endif

MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifeq (,$(filter ${V},YES yes y Y 1))
	QUIET_NOTICE  = @printf '%b' ${MAKECOLOR} 1>&2;
	QUIET_ENDCOLOR= @printf '%b' ${ENDCOLOR} 1>&2;
endif

MING_BASE:=
ifeq (${TARGET}, winagent)
CC=gcc
ifeq (${TARGET}, winagent)
CXX=g++-posix
else
CXX=g++
endif

ifneq (,$(shell which amd64-mingw32msvc-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=amd64-mingw32msvc-
	else
		MING_BASE:=
	endif
else
ifneq (,$(shell which i686-pc-mingw32-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=i686-pc-mingw32-
	else
		MING_BASE:=
	endif
else
ifneq (,$(shell which i686-w64-mingw32-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=i686-w64-mingw32-
	else
		MING_BASE:=
	endif
else
$(error No windows cross-compiler found!) #MING_BASE:=unknown-
endif
endif
endif
endif #winagent

####################
#### Target ########
####################

ifndef TARGET
	TARGET=failtarget
endif # TARGET

.PHONY: build
build: ${TARGET}
ifneq (${TARGET},failtarget)
	${MAKE} settings
	@echo
	${QUIET_NOTICE}
	@echo "Done building ${TARGET}"
	${QUIET_ENDCOLOR}
endif
	@echo

.PHONY: failtarget
failtarget:
	@echo "TARGET is required: "
	@echo "   make TARGET=manager   to build the manager"
	@echo "   make TARGET=local      - local version of manager"
	@echo "   make TARGET=hybrid     - hybrid version of manager"
	@echo "   make TARGET=agent    to build the unix agent"
	@echo "   make TARGET=winagent to build the windows agent"

.PHONY: help
help: failtarget
	@echo
	@echo "General options: "
	@echo "   make V=yes                   						Display full compiler messages. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DEBUG=yes               						Build with symbols and without optimization. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make INSTALLDIR=/path        						Wazuh's installation path. Mandatory when compiling the python interpreter from sources using PYTHON_SOURCE."
	@echo "   make RESOURCES_URL           						Set the Wazuh resources URL"
	@echo "   make EXTERNAL_SRC_ONLY=yes   						Combined with 'deps', it downloads only the external source code to be compiled as part of Wazuh building."
	@echo "   make USE_INOTIFY=yes         						Build with inotify support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_BIG_ENDIAN=yes      						Build with big endian support. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_SELINUX=yes         						Build with SELinux policies. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_AUDIT=yes           						Build with audit service support. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DISABLE_JEMALLOC=yes    						Not to build the JEMalloc library. Allowed values are 1, yes, YES, y, and Y, otherwise, the flag is ignored"
	@echo "   make OPTIMIZE_CPYTHON=yes    						Enable this flag to optimize the python interpreter build, which is performed when used PYTHON_SOURCE. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make PYTHON_SOURCE=yes       						Used along the deps target. Downloads the sources needed to build the python interpreter. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make IMAGE_TRUST_CHECKS=1     					This flag controls the dll and exe files signature verification mechanism. Allowed values are 0 (disabled), 1 (warning only) and 2 (full enforce). The default value is 1."
	@echo "   make CA_NAME="DigiCert Assured ID Root CA" 		This flag controls the CA name used to verify the dll and exe files signature. The default value is DigiCert Assured ID Root CA."
	@echo "   make deps HTTP_REQUEST_BRANCH=main 				Build dependencies for http-request tool from selected branch/tag only if submodule isn't checked out, valid at make deps stage. Allowed values are any existing branch/tag.
	@echo
	@echo "User options: "
	@echo "   make WAZUH_GROUP=wazuh       Set wazuh group"
	@echo "   make WAZUH_USER=wazuh        Set wazuh user"
	@echo
	@echo "Examples: Client with debugging enabled"
	@echo "   make TARGET=agent DEBUG=yes"

.PHONY: settings
settings:
	@echo
	@echo "General settings:"
	@echo "    TARGET:             ${TARGET}"
	@echo "    V:                  ${V}"
	@echo "    DEBUG:              ${DEBUG}"
	@echo "    INSTALLDIR:         ${INSTALLDIR}"
	@echo "    RESOURCES_URL:      ${RESOURCES_URL}"
	@echo "    EXTERNAL_SRC_ONLY:  ${EXTERNAL_SRC_ONLY}"
	@echo "    HTTP_REQUEST_BRANCH:${HTTP_REQUEST_BRANCH}"
	@echo "User settings:"
	@echo "    WAZUH_GROUP:        ${WAZUH_GROUP}"
	@echo "    WAZUH_USER:         ${WAZUH_USER}"
	@echo "USE settings:"
	@echo "    USE_INOTIFY:        ${USE_INOTIFY}"
	@echo "    USE_BIG_ENDIAN:     ${USE_BIG_ENDIAN}"
	@echo "    USE_SELINUX:        ${USE_SELINUX}"
	@echo "    USE_AUDIT:          ${USE_AUDIT}"
	@echo "    IMAGE_TRUST_CHECKS: ${IMAGE_TRUST_CHECKS}"
	@echo "    CA_NAME:            ${CA_NAME}"
	@echo "Compiler:"
	@echo "    CC                ${CC}"
	@echo "    MAKE              ${MAKE}"

BUILD_CMAKE_PROJECTS+=build_wazuh_cmake

${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}: ${libstdc++_path}
	cp $< $@
	${STRIP_TOOL} -x $@

${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME}: ${libgcc_s_path}
	cp $< $@
	${STRIP_TOOL} -x $@

.PHONY: server manager local hybrid agent selinux

ifeq (${MAKECMDGOALS},server)
$(error Do not use 'server' directly, use 'TARGET=manager')
endif
server manager: ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifeq (${MAKECMDGOALS},local)
$(error Do not use 'local' directly, use 'TARGET=local')
endif
local: ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifeq (${MAKECMDGOALS},hybrid)
$(error Do not use 'hybrid' directly, use 'TARGET=hybrid')
endif
hybrid: ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifeq (${MAKECMDGOALS},agent)
$(error Do not use 'agent' directly, use 'TARGET=agent')
endif

agent: ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifneq (,$(filter ${USE_SELINUX},YES yes y Y 1))
server manager local hybrid agent: selinux
endif

selinux: $(SELINUX_POLICY)

$(SELINUX_POLICY): $(SELINUX_MODULE)
	semodule_package -o $@ -m $?

$(SELINUX_MODULE): $(SELINUX_ENFORCEMENT)
	checkmodule -M -m -o $@ $?

WINDOWS_CMAKE_MODULES:=win32/wazuh_cmake_modules

ifeq (${MAKECMDGOALS},winagent)
$(error Do not use 'winagent' directly, use 'TARGET=winagent')
endif
.PHONY: winagent
winagent: ${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME} ${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}
	${MAKE} ${WINDOWS_CMAKE_MODULES} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1"
	cd win32/ && ./unix2dos.pl ossec.conf > default-ossec.conf
	cd win32/ && ./unix2dos.pl help.txt > help_win.txt
	cd win32/ && ./unix2dos.pl ../../etc/internal_options.conf > internal_options.conf
	cd win32/ && ./unix2dos.pl ../../etc/local_internal_options-win.conf > default-local_internal_options.conf
	cd win32/ && ./unix2dos.pl ../../LICENSE > LICENSE.txt
	cd win32/ && ./unix2dos.pl ../../VERSION.json > VERSION.json

win32/wazuh_cmake_modules:
	${MAKE} build_wazuh_cmake

####################
#### External ######
####################

# CPython build
ifneq (${TARGET},winagent)
ifneq (${TARGET},agent)
ifneq (,$(wildcard ${EXTERNAL_CPYTHON}))
server local hybrid: build_python
endif
endif
endif

TAR := tar -xf
GUNZIP := gunzip
GZIP := gzip
CURL := curl -so
DEPS_VERSION = 99-29585
RESOURCES_URL_BASE := https://packages.wazuh.com/deps/
RESOURCES_URL := $(RESOURCES_URL_BASE)$(DEPS_VERSION)
CPYTHON := cpython
PYTHON_SOURCE := no

ifneq (${TARGET}, winagent)
ifneq (,$(filter ${uname_S},Linux Darwin))
	cpu_arch := ${uname_M}
ifneq (,$(filter ${cpu_arch},x86_64 amd64))
	PRECOMPILED_ARCH := /amd64
else
ifneq (,$(filter ${cpu_arch},i386 i686))
	PRECOMPILED_ARCH := /i386
else
ifneq (,$(filter ${cpu_arch},aarch64 arm64))
	PRECOMPILED_ARCH := /aarch64
else
ifneq (,$(filter ${cpu_arch},armv8l armv7l arm32 armhf))
	PRECOMPILED_ARCH := /arm32
else
ifneq (,$(filter ${cpu_arch},ia64))
	PRECOMPILED_ARCH := /ia64
else
	PRECOMPILED_ARCH := /${uname_P}
endif
endif
endif
endif
endif
else
    cpu_arch := ${uname_M}
ifneq (,$(filter ${cpu_arch},unknown Unknown not))
	cpu_arch := ${uname_P}
endif
	PRECOMPILED_ARCH := /${cpu_arch}
endif
endif

# Define CPYTHON pre-compile
CPYTHON_ARCHIVE := cpython_x86_64
ifeq ($(PRECOMPILED_ARCH),/aarch64)
	CPYTHON_ARCHIVE := cpython_arm64
else
	CPYTHON_ARCHIVE := cpython_x86_64
endif

ifeq (,$(filter ${EXTERNAL_SRC_ONLY},YES yes y Y 1))
# If EXTERNAL_SRC_ONLY=YES is not defined, lets look for the precompiled lib
PRECOMPILED_RES := $(PRECOMPILED_OS)$(PRECOMPILED_ARCH)
endif

# Agent dependencies
EXTERNAL_RES := cJSON curl libdb libffi libyaml openssl procps sqlite zlib audit-userspace msgpack bzip2 nlohmann googletest libpcre2 libplist pacman libarchive popt lua rpm rocksdb lzma cpp-httplib benchmark libbpf-bootstrap dbus flatbuffers
ifneq (${TARGET},agent)
ifneq (${TARGET},winagent)
	# Manager extra dependency
	EXTERNAL_RES += $(CPYTHON) jemalloc flatbuffers simdjson spdlog yaml-cpp pugixml libmaxminddb date fmt abseil-cpp re2 protobuf rapidjson taskflow RxCpp concurrentqueue fast_float geo_db
endif
endif

# Remove libbpf-bootstrap and dbus if the target is winagent OR non-Linux OS
ifeq (${TARGET}, winagent)
	EXTERNAL_RES := $(filter-out libbpf-bootstrap dbus, $(EXTERNAL_RES))
else
ifneq (${uname_S}, Linux)
	EXTERNAL_RES := $(filter-out libbpf-bootstrap dbus, $(EXTERNAL_RES))
endif
endif

EXTERNAL_DIR := $(EXTERNAL_RES:%=external/%)
EXTERNAL_TAR := $(EXTERNAL_RES:%=external/%.tar.gz)

# Shared tools like dependencies
SHARED_RES := http-request
SHARED_TAR := $(SHARED_RES:%=shared_modules/%.tar.gz)

# Indexer plugin templates
INDEXER_PLUGINS_DIR := external/indexer-plugins
INDEXER_PLUGINS_BASE_URL := https://raw.githubusercontent.com/wazuh/wazuh-indexer-plugins
INDEXER_PLUGINS_STATES_PATH := plugins/setup/src/main/resources/templates/states
INDEXER_PLUGINS_STREAMS_PATH := plugins/setup/src/main/resources/templates/streams

# Base templates (always downloaded)
INDEXER_TEMPLATES_BASE := \
	fim-files.json \
	fim-registry-keys.json \
	fim-registry-values.json \
	inventory-browser-extensions.json \
	inventory-groups.json \
	inventory-hardware.json \
	inventory-hotfixes.json \
	inventory-interfaces.json \
	inventory-networks.json \
	inventory-packages.json \
	inventory-ports.json \
	inventory-processes.json \
	inventory-protocols.json \
	inventory-services.json \
	inventory-system.json \
	inventory-users.json \
	sca.json

# Additional templates for server target
INDEXER_TEMPLATES_SERVER_STATES := \
	vulnerabilities.json

INDEXER_TEMPLATES_SERVER_STREAMS :=

# WCS flat files
WCS_FLAT_DIR := external/wcs-flat-files
WCS_FLAT_STATELESS_PATH := ecs/stateless

# TODO: can I avoid the list and just bring everything in that dir?
WCS_FLAT_YAML_FILES := \
	access-management-ecs-flat.yml \
	applications-ecs-flat.yml \
	network-activity-ecs-flat.yml \
	other-ecs-flat.yml \
	security-ecs-flat.yml \
	system-activity-ecs-flat.yml

# Create WCS flat file paths
WCS_FLAT_FILES := $(WCS_FLAT_YAML_FILES:%=$(WCS_FLAT_DIR)/%)

# Select templates based on TARGET
ifeq (${TARGET}, agent)
INDEXER_TEMPLATES_STATES := $(INDEXER_TEMPLATES_BASE)
INDEXER_TEMPLATES_STREAMS :=
else
INDEXER_TEMPLATES_STATES := $(INDEXER_TEMPLATES_BASE) $(INDEXER_TEMPLATES_SERVER_STATES)
INDEXER_TEMPLATES_STREAMS := $(INDEXER_TEMPLATES_SERVER_STREAMS)
endif

INDEXER_TEMPLATE_FILES := $(INDEXER_TEMPLATES_STATES:%=$(INDEXER_PLUGINS_DIR)/%) $(INDEXER_TEMPLATES_STREAMS:%=$(INDEXER_PLUGINS_DIR)/%)

.PHONY: deps
deps: $(EXTERNAL_TAR) $(SHARED_TAR) $(INDEXER_TEMPLATE_FILES) $(WCS_FLAT_FILES)

external/$(CPYTHON).tar.gz:
# Python interpreter
ifeq (,$(filter ${PYTHON_SOURCE},YES yes y Y 1))
ifneq (,$(PRECOMPILED_RES))
external/$(CPYTHON).tar.gz: external-precompiled/$(CPYTHON).tar.gz
	test -e $(patsubst %.gz,%,$@) ||\
	($(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(CPYTHON_ARCHIVE).tar.gz &&\
	cd external && $(GUNZIP) $(patsubst external/%,%,$@) && $(TAR) $(patsubst external/%.gz,%,$@) && rm $(patsubst external/%.gz,%,$@))
	test -d $(patsubst %.tar.gz,%,$@) || (cd external && $(GZIP) $(patsubst external/%.gz,%,$@))

external-precompiled/$(CPYTHON).tar.gz:
	-$(CURL) external/$(patsubst external-precompiled/%,%,$@) $(RESOURCES_URL)/libraries/$(PRECOMPILED_RES)/$(patsubst external-precompiled/%,%,$@) || true
	-cd external && [ -f $(patsubst external-precompiled/%,%,$@) ] && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
else
external/$(CPYTHON).tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(CPYTHON_ARCHIVE).tar.gz
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif
else
external/$(CPYTHON).tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(CPYTHON_ARCHIVE).tar.gz
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif

# Remaining dependencies
ifneq (,$(PRECOMPILED_RES))
external/%.tar.gz: external-precompiled/%.tar.gz
	test -d $(patsubst %.tar.gz,%,$@) ||\
	($(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@) &&\
	cd external && $(GUNZIP) $(patsubst external/%,%,$@) && $(TAR) $(patsubst external/%.gz,%,$@) && rm $(patsubst external/%.gz,%,$@))
else
external/%.tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif

ifneq (,$(PRECOMPILED_RES))
external-precompiled/%.tar.gz:
	-$(CURL) external/$(patsubst external-precompiled/%,%,$@) $(RESOURCES_URL)/libraries/$(PRECOMPILED_RES)/$(patsubst external-precompiled/%,%,$@) || true
	-cd external && [ -f $(patsubst external-precompiled/%,%,$@) ] && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	-cd external && [ -f $(patsubst external-precompiled/%.gz,%,$@) ] && $(TAR) $(patsubst external-precompiled/%.gz,%,$@) || true
	-[ -f external/$(patsubst external-precompiled/%.gz,%,$@) ] && rm external/$(patsubst external-precompiled/%.gz,%,$@) || true
endif

# Shared tools
HTTP_REQUEST_URL := https://github.com/wazuh/wazuh-http-request/tarball/$(HTTP_REQUEST_BRANCH)

# Certificate bundle path for HTTPS connections (only if exists)
CA_BUNDLE := /etc/ssl/certs/ca-certificates.crt
CACERT_OPT := $(shell test -f $(CA_BUNDLE) && echo "--cacert $(CA_BUNDLE)" || echo "")

shared_modules/http-request.tar.gz:
	find $(patsubst %.tar.gz,%,$@) -type f -exec false {} + &&\
	((test -e $(patsubst %.gz,%,$@) || $(CURL) $@ $(CACERT_OPT) -L $(HTTP_REQUEST_URL)) &&\
	($(GUNZIP) $@ || (rm -f $@ && echo "Error decompressing $@ maybe wrong branch was supplied!" && false)) &&\
	$(TAR) $(patsubst %.gz,%,$@) --strip-components=1 -C $(patsubst %.tar.gz,%,$@) &&\
	rm $(patsubst %.gz,%,$@)) || true

# Indexer plugin templates download
# Get refs from get_git_refs.sh if INDEXER_PLUGINS_REFS is not set
ifdef INDEXER_PLUGINS_REFS
INDEXER_PLUGIN_REFS_LIST := $(INDEXER_PLUGINS_REFS)
else
INDEXER_PLUGIN_REFS_LIST := $(shell $(ROUTE_PATH)/../tools/get_git_refs.sh 2>/dev/null)
endif

$(INDEXER_PLUGINS_DIR):
	mkdir -p $(INDEXER_PLUGINS_DIR)

# Rule for streams templates (alerts.json)
$(INDEXER_PLUGINS_DIR)/alerts.json: | $(INDEXER_PLUGINS_DIR)
	@success=0; \
	for ref in $(INDEXER_PLUGIN_REFS_LIST); do \
		url="$(INDEXER_PLUGINS_BASE_URL)/$$ref/$(INDEXER_PLUGINS_STREAMS_PATH)/$(notdir $@)"; \
		echo "curl -f -s -o $@ $$url"; \
		if curl -f -s -o $@ "$$url" 2>/dev/null; then \
			success=1; \
			break; \
		fi; \
	done; \
	if [ $$success -eq 0 ]; then \
		echo "ERROR: Failed to download $(notdir $@) from any reference" >&2; \
		exit 1; \
	fi

# Rule for states templates (all other .json files)
$(INDEXER_PLUGINS_DIR)/%.json: | $(INDEXER_PLUGINS_DIR)
	@success=0; \
	for ref in $(INDEXER_PLUGIN_REFS_LIST); do \
		url="$(INDEXER_PLUGINS_BASE_URL)/$$ref/$(INDEXER_PLUGINS_STATES_PATH)/$(notdir $@)"; \
		echo "curl -f -s -o $@ $$url"; \
		if curl -f -s -o $@ "$$url" 2>/dev/null; then \
			success=1; \
			break; \
		fi; \
	done; \
	if [ $$success -eq 0 ]; then \
		echo "ERROR: Failed to download $(notdir $@) from any reference" >&2; \
		exit 1; \
	fi

# WCS flat files directory
$(WCS_FLAT_DIR):
	mkdir -p $(WCS_FLAT_DIR)

# Rule for WCS flat YAML files
$(WCS_FLAT_DIR)/%-ecs-flat.yml: | $(WCS_FLAT_DIR)
	@success=0; \
	subdir=$(patsubst %-ecs-flat.yml,%,$(@F)); \
	for ref in $(INDEXER_PLUGIN_REFS_LIST); do \
		url="$(INDEXER_PLUGINS_BASE_URL)/$$ref/$(WCS_FLAT_STATELESS_PATH)/$$subdir/docs/ecs_flat.yml"; \
		echo "curl -f -s -o $@ $$url"; \
		if curl -f -s -o $@ "$$url" 2>/dev/null; then \
			success=1; \
			break; \
		fi; \
	done; \
	if [ $$success -eq 0 ]; then \
		echo "ERROR: Failed to download $(notdir $@) from any reference" >&2; \
		exit 1; \
	fi

####################
#### Wazuh #########
####################

#### Wazuh cmake ###

build_wazuh_cmake:
	mkdir -p build && cd build && cmake .. -DTARGET=${TARGET} ${CMAKE_OPTS} ${WAZUH_RELEASE_TYPE} ${WAZUH_TEST} ${CMAKE_ENGINE_OPTS} && ${MAKE}

### wazuh-python ###

WPYTHON_DIR := ${INSTALLDIR}/framework/python
OPTIMIZE_CPYTHON?=no
WPYTHON_TAR=cpython.tar.gz
WLIBPYTHON=libpython3.12.so.1.0

ifneq (,$(filter ${OPTIMIZE_CPYTHON},YES yes y Y 1))
CPYTHON_FLAGS=--enable-optimizations
endif

wpython: install_dependencies install_framework install_api install_mitre

build_python:
ifeq (,${INSTALLDIR})
	$(error INSTALLDIR undefined. Run "${MAKE} TARGET=manager INSTALLDIR=/path" to build python from sources)
endif

ifeq (,$(wildcard ${EXTERNAL_CPYTHON}/python))
	export WPATH_LIB="'\$$\$$ORIGIN/../../../lib'" && \
	export LDFLAGS="-L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'${WPATH_LIB}'" && \
	export LIBSQLITE3_CFLAGS="-I${ROUTE_PATH}/${EXTERNAL_SQLITE}" && \
	export LIBSQLITE3_LIBS="-L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'${WPATH_LIB}'" && \
	export LIBFFI_CFLAGS="-I${ROUTE_PATH}/${EXTERNAL_LIBFFI}/include" && \
	export LIBFFI_LIBS="-L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'${WPATH_LIB}'" && \
	export CUSTOM_OPENSSL_INCLUDES="-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}/include" && \
	export CUSTOM_OPENSSL_LIBS="-lwazuhext" && \
	export CUSTOM_OPENSSL_LDFLAGS="-L${ROUTE_PATH} -Wl,-rpath,'${WPATH_LIB}'" && \
	export LD_LIBRARY_PATH=${ROUTE_PATH} && \
	cd ${EXTERNAL_CPYTHON} && \
	./configure --prefix="${WPYTHON_DIR}" --libdir="${WPYTHON_DIR}/lib" --enable-shared \
		--with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" \
		LDFLAGS="${ARCH_FLAGS} -L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'\$$\$$ORIGIN/../../../lib',--disable-new-dtags" \
		CPPFLAGS="-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}" $(CPYTHON_FLAGS) && ${MAKE}
endif

build_python: build_wazuh_cmake

install_python:
ifneq (,$(wildcard ${EXTERNAL_CPYTHON}))
	cd ${EXTERNAL_CPYTHON} && ${MAKE} install TEST_MODULES=no
else
	mkdir -p ${WPYTHON_DIR}
	cp external/${WPYTHON_TAR} ${WPYTHON_DIR}/${WPYTHON_TAR} && ${TAR} ${WPYTHON_DIR}/${WPYTHON_TAR} -C ${WPYTHON_DIR} && rm -rf ${WPYTHON_DIR}/${WPYTHON_TAR}
endif
	find ${WPYTHON_DIR} -name "*${WLIBPYTHON}" -exec ln -f {} ${INSTALLDIR}/lib/${WLIBPYTHON} \;

python_dependencies := requirements.txt

install_dependencies: install_python
ifneq (,$(wildcard ${EXTERNAL_CPYTHON}))
	${WPYTHON_DIR}/bin/python3 -m pip install --upgrade pip --index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple
	LD_LIBRARY_PATH="${INSTALLDIR}/lib" LDFLAGS="-L${INSTALLDIR}/lib" ${WPYTHON_DIR}/bin/pip3 install -r ../framework/${python_dependencies}  --index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple
endif

install_framework: install_python
	cd ../framework && ${WPYTHON_DIR}/bin/python3 -m pip install . --use-pep517 --prefix=${WPYTHON_DIR} && rm -rf build/
	chown -R root:${WAZUH_GROUP} ${WPYTHON_DIR}
	chmod -R o=- ${WPYTHON_DIR}

install_api: install_python
	cd ../api && ${WPYTHON_DIR}/bin/python3 -m pip install . --use-pep517 --prefix=${WPYTHON_DIR} && rm -rf build/

install_mitre: install_python
	cd ../tools/mitre && ${WPYTHON_DIR}/bin/python3 mitredb.py -d ${INSTALLDIR}/var/db/mitre.db

####################
#### Clean #########
####################

clean: clean-test clean-internals clean-external clean-windows clean-framework clean-config

clean-test:
	rm -Rf coverage-report/
	find . -name "*.gcno" -exec rm {} \;
	find . -name "*.gcda" -exec rm {} \;

clean-external: clean-wpython
ifneq ($(wildcard external/*/*),)
# Autotools-based dependencies - run make distclean/clean
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f Makefile.in distclean 2>/dev/null || true
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f win32/Makefile.gcc clean 2>/dev/null || true
	rm -f ${EXTERNAL_ZLIB}/contrib/minizip/*.o ${EXTERNAL_ZLIB}/contrib/minizip/*.a
	-cd ${EXTERNAL_OPENSSL} && ${MAKE} distclean 2>/dev/null || true
	-cd ${EXTERNAL_LIBYAML} && ${MAKE} distclean 2>/dev/null || true
	-cd ${EXTERNAL_CURL} && ${MAKE} distclean 2>/dev/null || true
	-cd ${EXTERNAL_AUDIT} && ${MAKE} distclean 2>/dev/null || true
	-cd ${EXTERNAL_LIBFFI} && ${MAKE} clean 2>/dev/null || true
	-cd ${EXTERNAL_BZIP2} && ${MAKE} clean 2>/dev/null || true
	-cd ${EXTERNAL_LIBPLIST} && ${MAKE} clean 2>/dev/null || true
	rm -rf ${EXTERNAL_LIBPLIST}bin/*
	-cd ${EXTERNAL_LIBPCRE2} && ${MAKE} distclean 2>/dev/null || true
	-cd ${EXTERNAL_LUA} && ${MAKE} clean 2>/dev/null || true
	rm -rf ${EXTERNAL_LUA}install/*
	-cd ${EXTERNAL_DBUS} && test -f configure && ${MAKE} distclean 2>/dev/null || true
	-cd ${EXTERNAL_LIBDB} && ${MAKE} realclean 2>/dev/null || true
	-cd ${EXTERNAL_LIBARCHIVE} && ${MAKE} clean 2>/dev/null || true
	-cd ${EXTERNAL_JEMALLOC} && ${MAKE} clean 2>/dev/null || true
# CMake-based dependencies - remove build directories only
	rm -rf $(EXTERNAL_GOOGLE_TEST)lib $(EXTERNAL_GOOGLE_TEST)build
	rm -rf $(EXTERNAL_GOOGLE_BENCHMARK)build
	rm -rf $(EXTERNAL_ROCKSDB)build
	rm -rf $(EXTERNAL_SIMDJSON)build
	rm -rf $(EXTERNAL_LIBBPF)build
	rm -rf $(EXTERNAL_FLATBUFFERS)build
	rm -rf $(EXTERNAL_FMT)build
	rm -rf $(EXTERNAL_SPDLOG)build
	rm -rf $(EXTERNAL_DATE)build
	rm -rf $(EXTERNAL_PUGIXML)build
	rm -rf $(EXTERNAL_YAMLCPP)build
	rm -rf $(EXTERNAL_ABSEILCPP)build
	rm -rf $(EXTERNAL_MAXMINDDB)build
	rm -rf $(EXTERNAL_RE2)build
	rm -rf $(EXTERNAL_PROTOBUF)build
	rm -rf $(EXTERNAL_LZMA)build
	rm -rf $(EXTERNAL_POPT)build
	rm -rf $(EXTERNAL_RPM)builddir
# Manually-compiled dependencies - remove object files and build artifacts
	rm -f $(EXTERNAL_PACMAN)lib/libalpm/*.a $(EXTERNAL_PACMAN)lib/libalpm/*.o
	rm -f $(EXTERNAL_JSON)*.o $(EXTERNAL_JSON)*.a
	rm -f $(EXTERNAL_SQLITE)*.o $(EXTERNAL_SQLITE)*.a
	rm -f $(EXTERNAL_PROCPS)*.o $(EXTERNAL_PROCPS)*.a
	rm -f $(EXTERNAL_MSGPACK)src/*.o $(EXTERNAL_MSGPACK)*.a
# Clean CMake ExternalProject stamp files
	rm -rf build/external/*-prefix
endif

clean-wpython:
ifneq ($(wildcard external/cpython/*),)
	-cd ${EXTERNAL_CPYTHON} && ${MAKE} clean && ${MAKE} distclean
endif

clean-deps:
	rm -rf $(EXTERNAL_DIR) $(EXTERNAL_TAR) shared_modules/http-request/* shared_modules/http-request/.??* $(INDEXER_PLUGINS_DIR) $(WCS_FLAT_DIR)

clean-internals:
# Wazuh libraries
	rm -f libwazuh.a
	rm -f libwazuh_test.a
	rm -f libwazuhext.*
	rm -f libwazuhshared.*
# Active responses
	rm -f default-firewall-drop
	rm -f pf
	rm -f npf
	rm -f ipfw
	rm -f firewalld-drop
	rm -f disable-account
	rm -f host-deny
	rm -f ip-customblock
	rm -f restart-wazuh
	rm -f route-null
	rm -f kaspersky
	rm -f wazuh-slack
	rm -f firewall-drop
	# Wazuh binaries
	rm -rf build
	rm -rf unit_tests/build*
	rm -f wazuh-manager-keystore
	rm -f wazuh-agentd
	rm -f wazuh-execd
	rm -f wazuh-logcollector
	rm -f wazuh-syscheckd
	rm -f wazuh-modulesd
	rm -f wazuh-remoted
	rm -f wazuh-monitord
	rm -f wazuh-authd
	rm -f wazuh-db
	rm -f wazuh-manager-modulesd
	rm -f wazuh-manager-remoted
	rm -f wazuh-manager-monitord
	rm -f wazuh-manager-authd
	rm -f wazuh-manager-db
	rm -f manage_agents
	rm -f verify-agent-conf
# Compilation libraries
	rm -rf libstdc++.so.6
	rm -rf libgcc_s.so.1
# Flatbuffers
	rm -rf shared_modules/utils/flatbuffers/build
	rm -rf shared_modules/utils/flatbuffers/include
# Selinux
	rm -f ${SELINUX_MODULE}
	rm -f ${SELINUX_POLICY}

clean-framework:
	${MAKE} -C ../framework clean

clean-windows:
# Configuration files
	rm -f win32/LICENSE.txt
	rm -f win32/help_win.txt
	rm -f win32/internal_options.conf
	rm -f win32/default-local_internal_options.conf
	rm -f win32/default-ossec.conf
	rm -f win32/default-ossec-pre6.conf
	rm -f win32/VERSION.json
# Active responses
	rm -f win32/restart-wazuh.exe
	rm -f win32/route-null.exe
	rm -f win32/netsh.exe
# Wazuh binaries
	rm -f win32/wazuh-agent.exe
	rm -f win32/wazuh-agent-eventchannel.exe
	rm -f win32/setup-windows.exe
	rm -f win32/setup-syscheck.exe
	rm -f win32/setup-iis.exe
	rm -f win32/os_win32ui.exe
	rm -f win32/manage_agents.exe
# Compilation libraries
	rm -f win32/libwinpthreadpatched.a
	rm -f win32/libwinpthread-1.dll
	rm -f win32/libstdc++-6.dll
	rm -f win32/libgcc_s_dw2-1.dll
	rm -f win32/libgcc_s_sjlj-1.dll

clean-config:
	rm -f ../etc/ossec.mc
	rm -f Config.OS
