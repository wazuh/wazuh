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

ifeq (${TARGET}, winagent)
WAZUH_LIB_OUTPUT_PATH := win32/
STRIP_TOOL := i686-w64-mingw32-strip
DLLTOOL := i686-w64-mingw32-dlltool
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
EXTERNAL_RAPIDJSON=external/rapidjson/
EXTERNAL_RXCPP=external/RxCpp/
EXTERNAL_YAMLCPP=external/yaml-cpp/
EXTERNAL_PUGIXML=external/pugixml/
EXTERNAL_MAXMINDDB=external/libmaxminddb/
EXTERNAL_PROTOBUF=external/protobuf/
EXTERNAL_DATE=external/date/
EXTERNAL_FAST_FLOAT=external/fast_float/
EXTERNAL_TASKFLOW=external/taskflow/
EXTERNAL_CONCURRENTQUEUE=external/concurrentqueue/
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
ifeq ($(TARGET),server)
WAZUH_USER?=wazuh-manager
WAZUH_GROUP?=wazuh-manager
else
WAZUH_USER?=wazuh
WAZUH_GROUP?=wazuh
endif
SHARED=so
SELINUX_MODULE=selinux/wazuh.mod
SELINUX_ENFORCEMENT=selinux/wazuh.te
SELINUX_POLICY=selinux/wazuh.pp
USE_INOTIFY=no
USE_BIG_ENDIAN=no
USE_AUDIT=no
MINGW_HOST=unknown
USE_MSGPACK_OPT=yes
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
GTEST_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
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
		OSSEC_CFLAGS+=-D_XOPEN_SOURCE=600 -D_GNU_SOURCE
		OSSEC_CFLAGS+=-pthread -I${EXTERNAL_PACMAN}lib/libalpm/ -I${EXTERNAL_LIBARCHIVE}libarchive
ifeq (${CHECK_ALPINE},YES)
		OSSEC_LIBS+=-lintl
endif
		OSSEC_LIBS+=-lrt -ldl -lm
		CC=gcc
ifeq (${CHECK_ARCHLINUX},YES)
		ARCH_FLAGS+=-lnghttp2 -lbrotlidec -lpsl
endif
else
ifeq (${uname_S},Darwin)
	OSSEC_CFLAGS+=-pthread
	SHARED=dylib
	OSSEC_LIBS+=-framework Security -framework CoreFoundation -framework SystemConfiguration
	PRECOMPILED_OS:=darwin
else
ifeq (${uname_S},FreeBSD)
		OSSEC_CFLAGS+=-pthread -I/usr/local/include
		PRECOMPILED_OS:=freebsd
else
ifeq (${uname_S},NetBSD)
		OSSEC_CFLAGS+=-pthread
		PRECOMPILED_OS:=netbsd
else
ifeq (${uname_S},OpenBSD)
		OSSEC_CFLAGS+=-pthread
		PRECOMPILED_OS:=openbsd
else
	    # Unknow platform
endif # OpenBSD
endif # NetBSD
endif # FreeBSD
endif # Darwin
endif # Linux
else
	    # There is a bug in the delay load mechanism for MinGW 32-bits executables (https://www.sourceware.org/bugzilla/show_bug.cgi?id=22676)
		# The workaround is to remove the __declspec(dllimport) from the function declaration in the executables (https://www.sourceware.org/bugzilla/show_bug.cgi?id=14339)
		SHARED=dll
		# We link against a patched libwinpthread.a library that no contains version.o (version.rc) to avoid including the resource in the executables due to the "--whole-archive" flag
		OSSEC_CFLAGS+=-Wl,-L,win32/ -Wl,-Bstatic,--whole-archive -lwinpthreadpatched -Wl,--no-whole-archive -Wl,-Bdynamic -ldelayimp -pthread -DBUILDING_LIBCURL="" -DPCRE2_EXP_DECL=""
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
	OSSEC_CFLAGS+=-g
	CMAKE_OPTS+=-DCMAKE_SYMBOLS_IN_RELEASE=ON
	ifeq (,$(filter ${DEBUG},YES yes y Y 1))
		OSSEC_CFLAGS+=-DNDEBUG
		OFLAGS+=-O2
	endif
else
	ifneq (,$(filter ${DEBUG},YES yes y Y 1))
		OSSEC_CFLAGS+=-g
	else
		OSSEC_CFLAGS+=-DNDEBUG
		OFLAGS+=-O2
	endif
endif

OSSEC_CFLAGS+=${OFLAGS}

OSSEC_CFLAGS+=-pipe -Wall -Wextra -std=gnu99

OSSEC_CFLAGS += ${CFLAGS}
OSSEC_LIBS += $(LIBS)

CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[37;1m"
MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifeq (,$(filter ${V},YES yes y Y 1))
	QUIET_CC      = @printf '    %b %b\n' ${CCCOLOR}CC${ENDCOLOR} ${SRCCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_LINK    = @printf '    %b %b\n' ${LINKCOLOR}LINK${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_CCBIN   = @printf '    %b %b\n' ${LINKCOLOR}CC${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_INSTALL = @printf '    %b %b\n' ${LINKCOLOR}INSTALL${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_RANLIB  = @printf '    %b %b\n' ${LINKCOLOR}RANLIB${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_NOTICE  = @printf '%b' ${MAKECOLOR} 1>&2;
	QUIET_ENDCOLOR= @printf '%b' ${ENDCOLOR} 1>&2;
endif

MING_BASE:=
ifeq (${TARGET}, winagent)
# Avoid passing environment variables such CFLAGS to external Makefiles
ifeq (${CC}, gcc)
	MAKEOVERRIDES=
endif

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
	MINGW_HOST="amd64-mingw32msvc"
else
ifneq (,$(shell which i686-pc-mingw32-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=i686-pc-mingw32-
	else
		MING_BASE:=
	endif
	MINGW_HOST="i686-pc-mingw32"
else
ifneq (,$(shell which i686-w64-mingw32-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=i686-w64-mingw32-
	else
		MING_BASE:=
	endif
	MINGW_HOST="i686-w64-mingw32"
else
$(error No windows cross-compiler found!) #MING_BASE:=unknown-
endif
endif
endif

ifneq (,$(wildcard /usr/i686-w64-mingw32/lib/libwinpthread-1.dll))
	WIN_PTHREAD_LIB:=/usr/i686-w64-mingw32/lib/libwinpthread-1.dll
else
ifneq (,$(wildcard /usr/i686-w64-mingw32/sys-root/mingw/bin/libwinpthread-1.dll))
	WIN_PTHREAD_LIB:=/usr/i686-w64-mingw32/sys-root/mingw/bin/libwinpthread-1.dll
endif
endif

ifneq (,$(wildcard /usr/i686-w64-mingw32/lib/libwinpthread.a))
	WIN_PTHREAD_STATIC_LIB:=/usr/i686-w64-mingw32/lib/libwinpthread.a
else
ifneq (,$(wildcard /usr/i686-w64-mingw32/sys-root/mingw/bin/libwinpthread.a))
	WIN_PTHREAD_STATIC_LIB:=/usr/i686-w64-mingw32/sys-root/mingw/bin/libwinpthread.a
endif
endif

endif #winagent

OSSEC_CC      		=${QUIET_CC}${MING_BASE}${CC}
OSSEC_SHARED  		=${QUIET_CCBIN}${MING_BASE}${CC} -shared
OSSEC_LINK    		=${QUIET_LINK}${MING_BASE}ar -crus
OSSEC_REMOVE_OBJECT =${QUIET_LINK}${MING_BASE}ar -d
OSSEC_RANLIB  		=${QUIET_RANLIB}${MING_BASE}ranlib
OSSEC_WINDRES 		=${QUIET_CCBIN}${MING_BASE}windres

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
	@echo "   make TARGET=server   to build the server"
	@echo "   make TARGET=local      - local version of server"
	@echo "   make TARGET=hybrid     - hybrid version of server"
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
	@echo "   make USE_MSGPACK_OPT=yes     						Use default architecture for building msgpack library. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DISABLE_JEMALLOC=yes    						Not to build the JEMalloc library. Allowed values are 1, yes, YES, y, and Y, otherwise, the flag is ignored"
	@echo "   make OFLAGS=-Ox              						Overrides optimization level"
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
	@echo "    DATABASE:           ${DATABASE}"
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
	@echo "Mysql settings:"
	@echo "    includes:           ${MI}"
	@echo "    libs:               ${ML}"
	@echo "Pgsql settings:"
	@echo "    includes:           ${PI}"
	@echo "    libs:               ${PL}"
	@echo "Compiler:"
	@echo "    CFLAGS            ${OSSEC_CFLAGS}"
	@echo "    LIBS              ${OSSEC_LIBS}"
	@echo "    CC                ${CC}"
	@echo "    MAKE              ${MAKE}"

BUILD_CMAKE_PROJECTS+=build_wazuh_cmake

${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}: ${libstdc++_path}
	cp $< $@
	${STRIP_TOOL} -x $@

${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME}: ${libgcc_s_path}
	cp $< $@
	${STRIP_TOOL} -x $@

.PHONY: server local hybrid agent selinux

ifeq (${MAKECMDGOALS},server)
$(error Do not use 'server' directly, use 'TARGET=server')
endif
server: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifeq (${MAKECMDGOALS},local)
$(error Do not use 'local' directly, use 'TARGET=local')
endif
local: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifeq (${MAKECMDGOALS},hybrid)
$(error Do not use 'hybrid' directly, use 'TARGET=hybrid')
endif
hybrid: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifeq (${MAKECMDGOALS},agent)
$(error Do not use 'agent' directly, use 'TARGET=agent')
endif

agent: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}

ifneq (,$(filter ${USE_SELINUX},YES yes y Y 1))
server local hybrid agent: selinux
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
winagent: external win32/libwinpthread-1.dll win32/libwinpthreadpatched.a ${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME} ${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}
	${MAKE} ${WAZUHEXT_LIB} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1" LIBS="-lwsock32 -lws2_32 -lcrypt32"
	${MAKE} ${WINDOWS_CMAKE_MODULES} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1"
	cd win32/ && ./unix2dos.pl ossec.conf > default-ossec.conf
	cd win32/ && ./unix2dos.pl help.txt > help_win.txt
	cd win32/ && ./unix2dos.pl ../../etc/internal_options.conf > internal_options.conf
	cd win32/ && ./unix2dos.pl ../../etc/local_internal_options-win.conf > default-local_internal_options.conf
	cd win32/ && ./unix2dos.pl ../../LICENSE > LICENSE.txt
	cd win32/ && ./unix2dos.pl ../../VERSION.json > VERSION.json

win32/wazuh_cmake_modules: $(WAZUHEXT_LIB) $(EXTERNAL_LIBS_NO_WHOLE)
	${MAKE} build_wazuh_cmake

win32/libwinpthread-1.dll: ${WIN_PTHREAD_LIB}
	cp $< $@

win32/libwinpthreadpatched.a: ${WIN_PTHREAD_STATIC_LIB}
	cp $< $@
	${OSSEC_REMOVE_OBJECT} $@ version.o

####################
#### External ######
####################

ZLIB_LIB    = $(EXTERNAL_ZLIB)/libz.a
MINIZIP_LIB = $(EXTERNAL_ZLIB)/contrib/minizip/libminizip.a
OPENSSL_LIB = $(EXTERNAL_OPENSSL)libssl.a
CRYPTO_LIB 	= $(EXTERNAL_OPENSSL)libcrypto.a
LIBPLIST_LIB = $(EXTERNAL_LIBPLIST)/bin/lib/libplist-2.0.a
SQLITE_LIB  = $(EXTERNAL_SQLITE)libsqlite3.a
JSON_LIB    = $(EXTERNAL_JSON)libcjson.a
PROCPS_LIB  = $(EXTERNAL_PROCPS)/libproc.a
DB_LIB      = $(EXTERNAL_LIBDB).libs/libdb-18.1.a
LIBALPM_LIB  = $(EXTERNAL_PACMAN)lib/libalpm/libalpm.a
LIBARCHIVE_LIB  = $(EXTERNAL_LIBARCHIVE).libs/libarchive.a
LIBYAML_LIB = $(EXTERNAL_LIBYAML)src/.libs/libyaml.a
LIBCURL_LIB = $(EXTERNAL_CURL)lib/.libs/libcurl.a
AUDIT_LIB 	= $(EXTERNAL_AUDIT)lib/.libs/libaudit.a
LIBFFI_LIB 	= $(EXTERNAL_LIBFFI)$(TARGET)/.libs/libffi.a
MSGPACK_LIB = $(EXTERNAL_MSGPACK)libmsgpack.a
BZIP2_LIB   = $(EXTERNAL_BZIP2)libbz2.a
LIBPCRE2_LIB = $(EXTERNAL_LIBPCRE2).libs/libpcre2-8.a
POPT_LIB = $(EXTERNAL_POPT)build/output/src/.libs/libpopt.a
RPM_LIB = $(EXTERNAL_RPM)builddir/librpm.a
JEMALLOC_LIB = $(EXTERNAL_JEMALLOC)lib/libjemalloc.so.2
ROCKSDB_LIB = $(EXTERNAL_ROCKSDB)build/librocksdb.so
SIMDJSON_LIB = $(EXTERNAL_SIMDJSON)build/libsimdjson.a
ABSEILCPP_LIB = $(EXTERNAL_ABSEILCPP)build/build_result/lib*/libabsl_*.a
RE2_LIB = $(EXTERNAL_RE2)build/libre2.a
FLATBUFFERS_LIB = $(EXTERNAL_FLATBUFFERS)build/libflatbuffers.a
SPDLOG_LIB = $(EXTERNAL_SPDLOG)build/libspdlog.a
YAMLCPP_LIB = $(EXTERNAL_YAMLCPP)build/libyaml-cpp.a
PUGIXML_LIB = $(EXTERNAL_PUGIXML)build/libpugixml.a
MAXMINDDB_LIB = $(EXTERNAL_MAXMINDDB)build/libmaxminddb.a
PROTOBUF_LIB = $(EXTERNAL_PROTOBUF)build/libprotobuf.a
DATE_LIB = $(EXTERNAL_DATE)build/libdate-tz.a
FMT_LIB = $(EXTERNAL_FMT)build/libfmt.a
LZMA_LIB = $(EXTERNAL_LZMA)build/liblzma.a
LUA_LIB = ${EXTERNAL_LUA}liblua.a
LIBBPF_LIB = $(EXTERNAL_LIBBPF)build/modern.bpf.o
DBUS_LIB = $(EXTERNAL_DBUS)lib/libdbus-1.a

EXTERNAL_LIBS_NO_WHOLE := $(FLATBUFFERS_LIB)
EXTERNAL_LIBS := $(JSON_LIB) $(ZLIB_LIB) $(OPENSSL_LIB) $(CRYPTO_LIB) $(SQLITE_LIB) $(LIBYAML_LIB) $(LIBPCRE2_LIB)

# Adding libcurl only on Windows, Linux and MacOS
ifeq (${TARGET},winagent)
	EXTERNAL_LIBS += $(LIBCURL_LIB)
else ifeq (${uname_S},Linux)
	EXTERNAL_LIBS += $(LIBCURL_LIB)
else ifeq (${uname_S},Darwin)
	EXTERNAL_LIBS += $(LIBCURL_LIB)
endif

# Adding libraries only for server
ifeq (${TARGET},server)
	EXTERNAL_LIBS_NO_WHOLE += $(ROCKSDB_LIB) $(SIMDJSON_LIB)
	EXTERNAL_LIBS += $(LZMA_LIB) $(MINIZIP_LIB)
endif

ifneq (${TARGET},winagent)
EXTERNAL_LIBS += $(MSGPACK_LIB) $(BZIP2_LIB)
ifneq (${TARGET},agent)
EXTERNAL_LIBS += $(LIBFFI_LIB)
endif
ifeq (${uname_S},Linux)
EXTERNAL_LIBS += ${DBUS_LIB} ${LUA_LIB} ${RPM_LIB} ${POPT_LIB}
EXTERNAL_LIBS += ${AUDIT_LIB}
EXTERNAL_LIBS += $(PROCPS_LIB) $(LIBALPM_LIB) $(LIBARCHIVE_LIB)
endif
endif
ifeq (${uname_S},Darwin)
EXTERNAL_LIBS += ${LIBPLIST_LIB}
endif

.PHONY: external test_external
external: test_external $(EXTERNAL_LIBS) $(JEMALLOC_LIB) $(EXTERNAL_LIBS_NO_WHOLE)

ifneq (,$(filter ${TEST},YES yes y Y 1)$(filter $(ENGINE_TEST),YES yes y Y 1))
external: build_gtest build_benchmark
# only auto-define the CMake flag if TEST was NOT provided
ifeq ($(TEST),)
  CMAKE_ENGINE_OPTS = -DWAZUH_ENGINE_TEST=ON
else
  $(warning TEST is defined; skipping CMake engine test option)
endif
endif

ifeq (${TARGET},server)
external: $(ROCKSDB_LIB) $(SIMDJSON_LIB) $(SPDLOG_LIB) $(YAMLCPP_LIB) $(PUGIXML_LIB) $(MAXMINDDB_LIB) $(DATE_LIB) $(FMT_LIB) $(FAST_FLOAT_LIB) $(PROTOBUF_LIB) $(ABSEILCPP_LIB) $(RE2_LIB)
endif

ifeq (${uname_S},Linux)
ifneq (${TARGET},winagent)
external: ${LIBBPF_LIB}
endif
endif

ifneq (${TARGET},winagent)
ifneq (${TARGET},agent)
ifneq (,$(wildcard ${EXTERNAL_CPYTHON}))
external: build_python
endif
endif
endif

test_external:
ifeq ($(wildcard external/*/*),)
	$(error No external directory found. Run "${MAKE} deps" before compiling external libraries)
endif

#### OpenSSL ##########

OPENSSL_FLAGS = enable-weak-ssl-ciphers no-shared

ifeq (${uname_M}, i386)
ifeq ($(findstring BSD,${uname_S}), BSD)
	OPENSSL_FLAGS += no-asm
endif
endif

${CRYPTO_LIB}: ${OPENSSL_LIB}

${OPENSSL_LIB}:
ifeq (${TARGET},winagent)
	cd ${EXTERNAL_OPENSSL} && CC=${MING_BASE}${CC} RC=${MING_BASE}windres ./Configure $(OPENSSL_FLAGS) mingw && ${MAKE} build_libs
else
ifeq (${uname_S},Darwin)
ifeq (${uname_M},arm64)
	cd ${EXTERNAL_OPENSSL} && ./Configure $(OPENSSL_FLAGS) darwin64-arm64-cc && ${MAKE} build_libs
else
	cd ${EXTERNAL_OPENSSL} && ./Configure $(OPENSSL_FLAGS) darwin64-x86_64-cc && ${MAKE} build_libs
endif
else
	cd ${EXTERNAL_OPENSSL} && ./config $(OPENSSL_FLAGS) && ${MAKE} build_libs
endif
endif

#### libbpf-bootstrap #########

$(LIBBPF_LIB):
	cd $(EXTERNAL_LIBBPF) && mkdir -p build && cd build && cmake .. && ${MAKE}

### rocks db ###

${ROCKSDB_LIB}:
	cd $(EXTERNAL_ROCKSDB) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DWITH_GFLAGS=0 -DWITH_TESTS=0 -DWITH_BENCHMARK_TOOLS=0 -DWITH_TOOLS=0 -DUSE_RTTI=1 -DROCKSDB_BUILD_SHARED=1 -DWITH_BZ2=1 -DBZIP2_INCLUDE_DIR=$(realpath $(EXTERNAL_BZIP2)) -DBZIP2_LIBRARIES=$(realpath $(BZIP2_LIB)) -DCMAKE_POSITION_INDEPENDENT_CODE=1 -DWITH_ALL_TESTS=0 -DWITH_RUNTIME_DEBUG=0 -DWITH_TRACE_TOOLS=0 -DPORTABLE=1 && ${MAKE}

### simdjson ###
${SIMDJSON_LIB}:
	cd $(EXTERNAL_SIMDJSON) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DSIMDJSON_DEVELOPER_MODE=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}

## abseilcpp ###
${ABSEILCPP_LIB}:
	mkdir -p $(EXTERNAL_ABSEILCPP)/build
	cd $(EXTERNAL_ABSEILCPP)/build && \
	  cmake .. \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DABSL_BUILD_TESTING=OFF \
	    -DABSL_USE_GOOGLETEST_HEAD=OFF \
	    -DCMAKE_CXX_STANDARD=17 \
		-DCMAKE_POSITION_INDEPENDENT_CODE=1 \
	    -DCMAKE_INSTALL_PREFIX=./build_result && \
	  make install

${RE2_LIB}: $(ABSEILCPP_LIB)
	mkdir -p $(EXTERNAL_RE2)build && \
	cd $(EXTERNAL_RE2)build && \
	cmake .. \
	-DCMAKE_BUILD_TYPE=Release \
	-DRE2_BUILD_TESTING=OFF \
	-DCMAKE_CXX_STANDARD=17 \
	-DBUILD_SHARED_LIBS=OFF \
	-DCMAKE_PREFIX_PATH=${ROUTE_PATH}/${EXTERNAL_ABSEILCPP}/build/build_result \
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	-DCMAKE_INSTALL_PREFIX=./result && \
	${MAKE}

## abseilcpp ###
${FLATBUFFERS_LIB}:
	cd $(EXTERNAL_FLATBUFFERS) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=0 -DFLATBUFFERS_INSTALL=0 -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}
	test -f $(EXTERNAL_FLATBUFFERS)build/flatc || (echo "ERROR: flatc compiler not found at: $(EXTERNAL_FLATBUFFERS)build/flatc" && exit 1)

### spdlog ###
${SPDLOG_LIB}:
	cd $(EXTERNAL_SPDLOG) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_BUILD_TESTS=OFF -DSPDLOG_BUILD_BENCH=OFF -DSPDLOG_FMT_EXTERNAL=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON && ${MAKE}

### yaml-cpp ###
${YAMLCPP_LIB}:
	cd $(EXTERNAL_YAMLCPP) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TOOLS=OFF -DYAML_CPP_BUILD_TESTS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}

### pugixml ###
${PUGIXML_LIB}:
	cd $(EXTERNAL_PUGIXML) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DPUGIXML_BUILD_TESTS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}

### maxminddb ###
${MAXMINDDB_LIB}:
	cd $(EXTERNAL_MAXMINDDB) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}

### protobuf ###
${PROTOBUF_LIB}:
	cd $(EXTERNAL_PROTOBUF) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON && ${MAKE}

### date ###
${DATE_LIB}:
	cd $(EXTERNAL_DATE) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_DATE_TESTING=OFF -DUSE_SYSTEM_TZ_DB=OFF -DBUILD_TZ_LIB=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON && ${MAKE}

### fmt ###
${FMT_LIB}:
	cd $(EXTERNAL_FMT) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DFMT_TEST=OFF -DFMT_DOC=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON && ${MAKE}

### lzma ###
${LZMA_LIB}:
	cd $(EXTERNAL_LZMA) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=0 -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}

#### libplist ##########

${LIBPLIST_LIB}:
	cd ${EXTERNAL_LIBPLIST} && ./autogen.sh --prefix=${ROUTE_PATH}/${EXTERNAL_LIBPLIST}bin && ${MAKE} && ${MAKE} install

#### libffi ##########

LIBFFI_FLAGS = "CFLAGS=-fPIC"

${LIBFFI_LIB}:
	cd ${EXTERNAL_LIBFFI} && test -e server || (./configure $(LIBFFI_FLAGS) && ${MAKE})
ifneq (${TARGET},server)
	cd ${EXTERNAL_LIBFFI} && test -e server && mv server $(TARGET) || true
endif

#### zlib ##########

$(ZLIB_LIB):
ifeq (${TARGET},winagent)
	cd ${EXTERNAL_ZLIB} && cp zconf.h.in zconf.h && ${MAKE} -f win32/Makefile.gcc PREFIX=${MING_BASE} libz.a
else
	cd ${EXTERNAL_ZLIB} && CFLAGS=-fPIC ./configure && ${MAKE} libz.a
endif

ZLIB_INCLUDE=-I./${EXTERNAL_ZLIB}

#### minizip ##########

$(MINIZIP_LIB): $(ZLIB_LIB)
	${QUIET_CC}cd ${EXTERNAL_ZLIB}/contrib/minizip && ${MING_BASE}${CC} -fPIC -c unzip.c ioapi.c -I../../ && ar rcs libminizip.a unzip.o ioapi.o

#### bzip2 ##########

$(BZIP2_LIB):
	cd ${EXTERNAL_BZIP2} && ${MAKE} CFLAGS="-fpic -Wall -O2 -D_FILE_OFFSET_BITS=64" libbz2.a

#### SQLite #########

sqlite_c = ${EXTERNAL_SQLITE}sqlite3.c
sqlite_o = ${EXTERNAL_SQLITE}sqlite3.o
SQLITE_CFLAGS = -DSQLITE_ENABLE_DBSTAT_VTAB=1

$(SQLITE_LIB): $(sqlite_o)
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

$(sqlite_o): $(sqlite_c)
	${OSSEC_CC} ${OSSEC_CFLAGS} -w -fPIC ${SQLITE_CFLAGS} -c $^ -o $@ -fPIC

#### cJSON #########

ifeq (${uname_S},Darwin)
JSON_SHFLAGS=-install_name @rpath/libcjson.$(SHARED)
endif

cjson_c := ${EXTERNAL_JSON}cJSON.c
cjson_o := $(cjson_c:.c=.o)

$(JSON_LIB): ${cjson_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

${EXTERNAL_JSON}%.o: ${EXTERNAL_JSON}%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

#### libyaml ##########

${LIBYAML_LIB}: $(EXTERNAL_LIBYAML)Makefile
	$(MAKE) -C $(EXTERNAL_LIBYAML)

$(EXTERNAL_LIBYAML)Makefile:
ifeq (${TARGET},winagent)
	cd $(EXTERNAL_LIBYAML) && CC=${MING_BASE}${CC} && CFLAGS=-fPIC ./configure --host=${MINGW_HOST} --enable-static=yes
else
	cd $(EXTERNAL_LIBYAML) && CFLAGS=-fPIC ./configure --enable-static=yes --enable-shared=no
endif

#### curl ##########

${LIBCURL_LIB}: $(EXTERNAL_CURL)Makefile
	${MAKE} -C $(EXTERNAL_CURL)lib

ifeq (${TARGET},winagent)
$(EXTERNAL_CURL)Makefile:
	cd $(EXTERNAL_CURL) && CFLAGS=-fPIC CC=${MING_BASE}${CC} ./configure --host=${MINGW_HOST} PREFIX=${MING_BASE} --enable-static=yes --disable-shared --with-schannel --disable-ldap --without-libidn2 --without-zstd && ${MAKE}
else
$(EXTERNAL_CURL)Makefile: $(OPENSSL_LIB)
ifeq (${uname_S},Linux)
ifneq (,$(filter ${uname_M},aarch64))
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-ldl -lpthread" ./configure --build=${uname_M}-unknown-linux-gnu --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" --disable-ldap --without-libidn2 --without-libpsl --without-brotli --without-nghttp2 --without-zstd
else
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-ldl -lpthread" ./configure --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" --disable-ldap --without-libidn2 --without-libpsl --without-brotli --without-nghttp2 --without-zstd
endif
else
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-lpthread" ./configure --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" --disable-ldap --without-libidn2 --without-brotli --without-nghttp2 --without-librtmp --without-zstd --without-libpsl
endif
endif

#### procps #########

PROCPS_INCLUDE=-I./${EXTERNAL_PROCPS}

procps_c := $(wildcard ${EXTERNAL_PROCPS}*.c)
procps_o := $(procps_c:.c=.o)
ifeq (${CHECK_ALPINE},YES)
ALPINE_DEBUG := "-DPATH_MAX=4096"
endif

${EXTERNAL_PROCPS}%.o: ${EXTERNAL_PROCPS}%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${ALPINE_DEBUG} -fPIC -c $^ -o $@

$(PROCPS_LIB): ${procps_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### Berkeley DB ######

ifeq (${uname_S},Linux)
${DB_LIB}: $(EXTERNAL_LIBDB)Makefile
	 ${MAKE} -C $(EXTERNAL_LIBDB) libdb.a

$(EXTERNAL_LIBDB)Makefile:
	cd ${EXTERNAL_LIBDB} && CPPFLAGS=-fPIC ../dist/configure --with-cryptography=no --disable-queue --disable-heap --disable-partition --disable-mutexsupport --disable-replication --disable-verify --disable-statistics ac_cv_func_pthread_yield=no
endif

#### libarchive ######

ifneq (${TARGET},winagent)
ifeq (${uname_S},Linux)
${LIBARCHIVE_LIB}: $(EXTERNAL_LIBARCHIVE)Makefile
	 ${MAKE} -C $(EXTERNAL_LIBARCHIVE) libarchive.la

$(EXTERNAL_LIBARCHIVE)Makefile:
	cd ${EXTERNAL_LIBARCHIVE} && CPPFLAGS=-fPIC ./configure --disable-acl --without-expat --without-iconv --without-xml2 --without-lz4 --without-lzma --without-zstd --without-bz2lib --without-openssl --without-libb2
endif
endif

#### libalpm ######

ifeq (${uname_S},Linux)

# we compile libalpm manually because pacman has a lot of dependencies and we only want to compile a few files
LIBALPM_LDCONFIG=`which ldconfig`
LIBALPM_CFLAGS=-DSYSHOOKDIR=\"/usr/share/libalpm/hooks\" \
			    -DLDCONFIG=\"${LIBALPM_LDCONFIG}\" \
			    -DFSSTATSTYPE="struct statvfs" \
			    -DSCRIPTLET_SHELL=\"/bin/sh\" \
			    -DHAVE_SYS_STATVFS_H \
			    -DLIB_VERSION=\"\" \
			    -DPATH_MAX=4096 \
			    -DHAVE_STRNLEN \
			    -DHAVE_LIBSSL \
			    -I${ROUTE_PATH}/${EXTERNAL_LIBARCHIVE}libarchive \
				-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include \
			    -I. \
			    -fPIC
${LIBALPM_LIB}: $(EXTERNAL_PACMAN)configure
	cd ${EXTERNAL_PACMAN}lib/libalpm && \
	$(CC) -c *.c ${LIBALPM_CFLAGS} && \
	ar rcs libalpm.a *.o
endif

#### Audit lib ####

${AUDIT_LIB}: $(EXTERNAL_AUDIT)Makefile
	${MAKE} -C $(EXTERNAL_AUDIT)lib CC=$(CC)

$(EXTERNAL_AUDIT)Makefile:
	cd $(EXTERNAL_AUDIT) && ./autogen.sh && ./configure CFLAGS=-fPIC --with-libcap-ng=no

#### msgpack #########

ifeq (,$(filter ${USE_MSGPACK_OPT},YES yes y Y 1))
        MSGPACK_ARCH=-march=i486
endif

ifneq (${TARGET},winagent)
msgpack_c := $(wildcard ${EXTERNAL_MSGPACK}src/*.c)
msgpack_o := $(msgpack_c:.c=.o)

${EXTERNAL_MSGPACK}src/%.o: ${EXTERNAL_MSGPACK}src/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${MSGPACK_ARCH} -fPIC -c $^ -o $@

$(MSGPACK_LIB): ${msgpack_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@
endif

#### PCRE2 lib #########

$(LIBPCRE2_LIB):
ifeq (${TARGET},winagent)
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC CC=${MING_BASE}${CC} ./configure --enable-jit=no --host=${MINGW_HOST} --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}
else
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC ./configure --enable-jit=auto --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}
endif

### popt lib ###

POPT_BUILD_DIR = $(EXTERNAL_POPT)build/

$(POPT_LIB): $(POPT_BUILD_DIR)Makefile
	 $(MAKE) -C $(POPT_BUILD_DIR)
$(POPT_BUILD_DIR)Makefile:
	mkdir -p $(POPT_BUILD_DIR) && cd $(POPT_BUILD_DIR) && cmake ..

### lua lib ###

$(LUA_LIB):
	cd ${EXTERNAL_LUA} && ${MAKE} all MYCFLAGS='-fPIC -DLUA_USE_LINUX' MYLIBS='-lm -ldl'

### rpm lib ###

RPM_BUILD_DIR = ${EXTERNAL_RPM}/builddir

RPM_INC_PATHS = -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include \
				-I${ROUTE_PATH}/${EXTERNAL_ZLIB} \
				-I${ROUTE_PATH}/${EXTERNAL_POPT}/src \
				-I${ROUTE_PATH}/${EXTERNAL_SQLITE} \
				-I${ROUTE_PATH}/${EXTERNAL_LUA} \

RPM_LIB_PATHS = -L${ROUTE_PATH}/${EXTERNAL_OPENSSL} \
				-L${ROUTE_PATH}/${EXTERNAL_ZLIB} \
				-L${ROUTE_PATH}/${EXTERNAL_POPT}/build/output/src/.libs/ \
				-L${ROUTE_PATH}/${EXTERNAL_SQLITE} \
				-L${ROUTE_PATH}/${EXTERNAL_LUA} \

RPM_CFLAGS = -fPIC ${RPM_INC_PATHS} ${RPM_LIB_PATHS}
RPM_CC = gcc

${RPM_LIB}: ${RPM_BUILD_DIR}/Makefile
	cd ${RPM_BUILD_DIR} && ${MAKE}

${RPM_BUILD_DIR}/Makefile: ${OPENSSL_LIB} ${ZLIB_LIB} ${POPT_LIB} ${SQLITE_LIB} $(LUA_LIB)
	mkdir -p ${RPM_BUILD_DIR} && cd ${RPM_BUILD_DIR} && cmake -E env CFLAGS="${RPM_CFLAGS}" CC=${RPM_CC} cmake ..

#### jemalloc ##########

$(JEMALLOC_LIB):
ifeq (${TARGET},server)
ifneq ($(wildcard external/jemalloc/configure),)
	cd ${EXTERNAL_JEMALLOC} && LDFLAGS=-s ./configure --disable-static --disable-cxx && ${MAKE}
else
	cd ${EXTERNAL_JEMALLOC} && LDFLAGS=-s ./autogen.sh --disable-static --disable-cxx && ${MAKE}
endif
endif

### dbus lib ###

DBUS_CONFIG_OPTS = --enable-static \
					--disable-shared \
					--disable-doxygen-docs \
					--disable-xml-docs \
					--disable-dependency-tracking \
					--disable-systemd \
					--prefix=${ROUTE_PATH}/${EXTERNAL_DBUS} \
					--includedir=${ROUTE_PATH}/${EXTERNAL_DBUS}include \
					--libdir=${ROUTE_PATH}/${EXTERNAL_DBUS}lib \
					--with-system-socket=/run/dbus/system_bus_socket

$(DBUS_LIB):
	cd ${EXTERNAL_DBUS} && CFLAGS=-fPIC CXXFLAGS=-fPIC LDFLAGS=-fPIC ./configure ${DBUS_CONFIG_OPTS} && ${MAKE} && ${MAKE} install

################################
#### External dependencies  ####
################################

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
#### OSSEC Libs ####
####################
ifeq (${TARGET}, winagent)
# libwazuhext
WAZUHEXT_DLL = libwazuhext.$(SHARED)
WAZUHEXT_LIB = libwazuhext.lib
WAZUHEXT_LIB_DEF = libwazuhext.def
else
WAZUHEXT_LIB = libwazuhext.$(SHARED)
endif

ifneq (,$(filter ${TEST},YES yes y Y 1))
LIBS_TEST=-lcmocka
CFLAGS_TEST=-g -O0 --coverage -DWAZUH_UNIT_TESTING

OSSEC_CFLAGS+=${CFLAGS_TEST}
OSSEC_LIBS+=${LIBS_TEST}
endif

#### Wazuh cmake ###
build_wazuh_cmake: $(WAZUHEXT_LIB) $(EXTERNAL_LIBS_NO_WHOLE)
	mkdir -p build && cd build && cmake .. -DTARGET=${TARGET} ${CMAKE_OPTS} ${WAZUH_RELEASE_TYPE} ${WAZUH_TEST} ${CMAKE_ENGINE_OPTS} && ${MAKE}

### libwazuhext #########

ifeq (${uname_S},Darwin)
WAZUH_SHFLAGS=-install_name @rpath/libwazuhext.$(SHARED)

$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $(WAZUH_SHFLAGS) -o $@ -Wl,-all_load $^ $(OSSEC_LIBS)
else
ifeq (${TARGET}, winagent)
$(WAZUHEXT_LIB): $(WAZUHEXT_DLL) $(WAZUHEXT_LIB_DEF)
	$(DLLTOOL) -D $(WAZUHEXT_DLL) --def $(WAZUHEXT_LIB_DEF) --output-delaylib $@

$(WAZUHEXT_DLL) $(WAZUHEXT_LIB_DEF): $(EXTERNAL_LIBS) win32/version-dll.o
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $(WAZUHEXT_DLL) -static-libgcc -Wl,--export-all-symbols -Wl,--add-stdcall-alias -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--output-def,$(WAZUHEXT_LIB_DEF) ${OSSEC_LIBS}

else
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
endif

### wazuh-gtest-gmock ###

build_gtest:
	cd $(EXTERNAL_GOOGLE_TEST) && mkdir -p build && cd build && cmake .. ${CMAKE_OPTS} ${GTEST_RELEASE_TYPE}  -DBUILD_GMOCK=ON -DBUILD_SHARED_LIBS=0 && ${MAKE} && cp -r lib ..

### wazuh-google-benchmark ###

build_benchmark:
	cd $(EXTERNAL_GOOGLE_BENCHMARK) && mkdir -p build && cd build && cmake .. -DBENCHMARK_ENABLE_TESTING=0 ${CMAKE_OPTS} && ${MAKE}

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
	$(error INSTALLDIR undefined. Run "${MAKE} TARGET=server INSTALLDIR=/path" to build python from sources)
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

build_python: $(WAZUHEXT_LIB)

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
#### Windows #######
####################

win32/version-dll.o: win32/version.rc
	${OSSEC_WINDRES} -DVER_TYPE=VFT_DLL -i $< -o $@

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
	rm -f ${cjson_o} $(EXTERNAL_JSON)libcjson.*
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f Makefile.in distclean
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f win32/Makefile.gcc clean
	rm -f ${EXTERNAL_ZLIB}/Makefile ${EXTERNAL_ZLIB}/zconf.h
	-cd ${EXTERNAL_OPENSSL} && ${MAKE} distclean
	-cd ${EXTERNAL_LIBYAML} && ${MAKE} distclean
	-cd ${EXTERNAL_CURL} && ${MAKE} distclean
	rm -f ${procps_o} $(PROCPS_LIB)
	rm -f $(sqlite_o) $(EXTERNAL_SQLITE)/libsqlite3.*
	-cd ${EXTERNAL_AUDIT} && ${MAKE} distclean
	-cd ${EXTERNAL_LIBFFI} && ${MAKE} clean
	rm -f $(msgpack_o) $(EXTERNAL_MSGPACK)libmsgpack.a
	-${MAKE} -C $(EXTERNAL_BZIP2) clean
	rm -rf $(EXTERNAL_GOOGLE_TEST)lib
	rm -rf $(EXTERNAL_GOOGLE_TEST)build
	rm -rf $(EXTERNAL_GOOGLE_BENCHMARK)build
	rm -rf $(EXTERNAL_ROCKSDB)build
	rm -rf $(EXTERNAL_SIMDJSON)build
	rm -rf $(EXTERNAL_LIBBPF)build
	rm -rf $(EXTERNAL_FLATBUFFERS)build
	rm -rf $(EXTERNAL_FMT)
	rm -rf $(EXTERNAL_SPDLOG)
	rm -rf $(EXTERNAL_RAPIDJSON)
	rm -rf $(EXTERNAL_RXCPP)
	rm -rf $(EXTERNAL_TASKFLOW)
	rm -rf $(EXTERNAL_DATE)
	rm -rf $(EXTERNAL_CONCURRENTQUEUE)
	rm -rf $(EXTERNAL_FAST_FLOAT)
	rm -rf $(EXTERNAL_PUGIXML)
	rm -rf $(EXTERNAL_YAMLCPP)
	rm -rf $(EXTERNAL_ABSEILCPP)
	rm -rf $(EXTERNAL_MAXMINDDB)
	rm -rf $(EXTERNAL_RE2)
	rm -rf $(EXTERNAL_PROTOBUF)
	rm -rf $(EXTERNAL_LZMA)build
	-cd ${EXTERNAL_LIBPLIST} && ${MAKE} clean && rm -rf bin/*
	-cd ${EXTERNAL_LIBPCRE2} && ${MAKE} distclean && rm -rf include/*
	rm -rf ${POPT_BUILD_DIR}
	rm -rf ${RPM_BUILD_DIR}
	-cd ${EXTERNAL_LUA} && ${MAKE} clean && rm -rf install/*
	rm -rf $(EXTERNAL_DBUS)lib $(EXTERNAL_DBUS)include

ifneq ($(wildcard external/libdb/build_unix/*),)
	cd ${EXTERNAL_LIBDB} && ${MAKE} realclean
endif

ifneq ($(wildcard external/libarchive/Makefile),)
	cd ${EXTERNAL_LIBARCHIVE} && ${MAKE} clean
endif

ifneq ($(wildcard external/jemalloc/Makefile),)
	cd ${EXTERNAL_JEMALLOC} && ${MAKE} clean
endif

ifneq ($(wildcard external/pacman/lib/libalpm/*),)
	rm -f $(EXTERNAL_PACMAN)lib/libalpm/libalpm.a
	rm -f $(EXTERNAL_PACMAN)lib/libalpm/*.o
endif
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
	rm -f wazuh-keystore
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
	rm -f wazuh-manager-execd
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
	rm -f win32/version-dll.o
	rm -f win32/libwinpthreadpatched.a
	rm -f win32/libwinpthread-1.dll
	rm -f win32/libstdc++-6.dll
	rm -f win32/libgcc_s_dw2-1.dll
	rm -f win32/libgcc_s_sjlj-1.dll

clean-config:
	rm -f ../etc/ossec.mc
	rm -f Config.OS
