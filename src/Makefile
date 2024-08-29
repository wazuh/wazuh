# Copyright (C) 2015, Wazuh Inc.
# TODO: mysql and postgresql?
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


libstdc++_path := $(shell sh -c 'g++ --print-file-name=libstdc++.so.6 2>/dev/null || echo not')
libgcc_s_path := $(shell sh -c 'g++ --print-file-name=libgcc_s.so.1 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++.so.6
LIBGCC_S_NAME := libgcc_s.so.1

STRIP_TOOL := strip

ifeq (, $(filter ${libstdc++_path}, not ${LIBSTDCPP_NAME}))
ifeq (, $(filter ${libgcc_s_path}, not ${LIBGCC_S_NAME}))
CPPLIBDEPS := ${LIBSTDCPP_NAME} ${LIBGCC_S_NAME}
endif
endif

HAS_CHECKMODULE = $(shell command -v checkmodule > /dev/null && echo YES)
HAS_SEMODULE_PACKAGE = $(shell command -v semodule_package > /dev/null && echo YES)

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
EXTERNAL_FLATBUFFERS=external/flatbuffers/
EXTERNAL_LZMA=external/lzma/
EXTERNAL_LUA=external/lua/
EXTERNAL_LIBPCRE2=external/libpcre2/
EXTERNAL_PROCPS=external/procps/
EXTERNAL_LIBDB=external/libdb/build_unix/
EXTERNAL_PACMAN=external/pacman/
EXTERNAL_LIBARCHIVE=external/libarchive/
EXTERNAL_JEMALLOC=external/jemalloc/
ifeq (${uname_S},Linux)
EXTERNAL_RPM=external/rpm/
EXTERNAL_POPT=external/popt/
endif
# XXX Becareful NO EXTRA Spaces here
PG_CONFIG?=pg_config
MY_CONFIG?=mysql_config
PRELUDE_CONFIG?=libprelude-config
WAZUH_GROUP?=wazuh
WAZUH_USER?=wazuh
SHARED=so
SELINUX_MODULE=selinux/wazuh.mod
SELINUX_ENFORCEMENT=selinux/wazuh.te
SELINUX_POLICY=selinux/wazuh.pp
SHARED_MODULES=shared_modules/
DBSYNC=${SHARED_MODULES}dbsync/
RSYNC=${SHARED_MODULES}rsync/
ROUTER=shared_modules/router/
CONTENT_MANAGER=shared_modules/content_manager/
VULNERABILITY_SCANNER=wazuh_modules/vulnerability_scanner/
SYSINFO=data_provider/
USE_PRELUDE?=no
USE_ZEROMQ?=no
USE_GEOIP?=no
USE_INOTIFY=no
USE_BIG_ENDIAN=no
USE_AUDIT=no
MINGW_HOST=unknown
USE_MSGPACK_OPT=yes
DISABLE_JEMALLOC?=no
DISABLE_SYSC?=no
DISABLE_CISCAT?=no
IMAGE_TRUST_CHECKS?=1
CA_NAME?=DigiCert Assured ID Root CA
HTTP_REQUEST_BRANCH?=v1.0.0

ifneq (,$(filter ${TEST},YES yes y Y 1))
DBSYNC_TEST=-DUNIT_TEST=ON #--coverage
RSYNC_TEST=-DUNIT_TEST=ON #--coverage
SYSINFO_TEST=-DUNIT_TEST=ON #--coverage
WAZUH_TEST=-DUNIT_TEST=ON #--coverage
endif
ifneq (,$(filter ${DEBUG},YES yes y Y 1))
SHARED_MODULES_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
GTEST_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
SYSINFO_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
WAZUH_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
endif

ifeq (${COVERITY}, YES)
	SHARED_MODULES_RELEASE_TYPE+=-DCOVERITY=1
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

ONEWAY?=no
CLEANFULL?=no

DEFINES=-DOSSECHIDS
DEFINES+=-DUSER=\"${WAZUH_USER}\"
DEFINES+=-DGROUPGLOBAL=\"${WAZUH_GROUP}\"

DEFINES+=-D${uname_S}
ifeq (${uname_S},Linux)
		PRECOMPILED_OS:=linux
		DEFINES+=-DINOTIFY_ENABLED -D_XOPEN_SOURCE=600 -D_GNU_SOURCE
		OSSEC_CFLAGS+=-pthread -I${EXTERNAL_PACMAN}lib/libalpm/ -I${EXTERNAL_LIBARCHIVE}libarchive
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../../lib'
		OSSEC_LIBS+=-lrt -ldl -lm
		OSSEC_LDFLAGS+=-pthread -lrt -ldl
		AR_LDFLAGS+=-pthread -lrt -ldl
		OSSEC_CFLAGS+=-Wl,--start-group
		USE_AUDIT=yes
		CC=gcc
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
		OSSEC_CFLAGS+=-I$(EXTERNAL_AUDIT)lib
endif
endif # Linux

ifeq (${IMAGE_TRUST_CHECKS}, 0)
	DEFINES+=-DIMAGE_TRUST_CHECKS=0
else ifeq (${IMAGE_TRUST_CHECKS}, 1)
	DEFINES+=-DIMAGE_TRUST_CHECKS=1
else ifeq (${IMAGE_TRUST_CHECKS}, 2)
	DEFINES+=-DIMAGE_TRUST_CHECKS=2
endif

DEFINES+=-DCA_NAME='${CA_NAME}'

ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
	DEFINES+=-DENABLE_SYSC
endif

ifeq (,$(filter ${DISABLE_CISCAT},YES yes y Y 1))
	DEFINES+=-DENABLE_CISCAT
endif

ifneq (,$(filter ${DEBUGAD},YES yes y Y 1))
	DEFINES+=-DDEBUGAD
endif

ifneq (,$(filter ${DEBUG},YES yes y Y 1))
	OSSEC_CFLAGS+=-g
	AR_LDFLAGS+=-g
else
	OSSEC_CFLAGS+=-DNDEBUG
	OFLAGS+=-O2
	AR_LDFLAGS+=-s
endif #DEBUG

OSSEC_CFLAGS+=${OFLAGS}
OSSEC_LDFLAGS+=${OFLAGS}
AR_LDFLAGS+=${OFLAGS}

DBSYNC_LIB+=-ldbsync
RSYNC_LIB+=-lrsync

OSSEC_LDFLAGS+=-L${DBSYNC}build/lib
OSSEC_LDFLAGS+=-L${RSYNC}build/lib

ifeq (${TARGET},server)
	WAZUH_LIBS+=-lrouter
	WAZUH_LDFLAGS+=-Lbuild/shared_modules/router
endif

ifneq (,$(filter ${CLEANFULL},YES yes y Y 1))
	DEFINES+=-DCLEANFULL
endif

ifneq (,$(filter ${ONEWAY},YES yes y Y 1))
	DEFINES+=-DONEWAY_ENABLED
endif

ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
        DEFINES+=-DENABLE_AUDIT
endif

ifeq (${COVERITY}, YES)
	DEFINES+=-D__coverity__
endif

OSSEC_CFLAGS+=${DEFINES}
OSSEC_CFLAGS+=-pipe -Wall -Wextra -std=gnu99
OSSEC_CFLAGS+=-I./ -I./headers/ -I${EXTERNAL_OPENSSL}include -I$(EXTERNAL_JSON) -I${EXTERNAL_LIBYAML}include -I${EXTERNAL_CURL}include -I${EXTERNAL_MSGPACK}include -I${EXTERNAL_BZIP2} -I${SHARED_MODULES}common -I${DBSYNC}include -I${RSYNC}include -I${SYSINFO}include  -I${EXTERNAL_LIBPCRE2}include -I${EXTERNAL_RPM}/builddir/output/include -I${ROUTER}include -I${CONTENT_MANAGER}include -I${VULNERABILITY_SCANNER}include -I./shared_modules/

OSSEC_CFLAGS += ${CFLAGS}
OSSEC_LDFLAGS += ${LDFLAGS}
AR_LDFLAGS += ${LDFLAGS}
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

CXX=g++

OSSEC_CC      		=${QUIET_CC}${CC}
OSSEC_CCBIN   		=${QUIET_CCBIN}${CC}
OSSEC_CXXBIN  		=${QUIET_CCBIN}${CXX}
OSSEC_SHARED  		=${QUIET_CCBIN}${CC} -shared
OSSEC_LINK    		=${QUIET_LINK}ar -crus
OSSEC_REMOVE_OBJECT =${QUIET_LINK}ar -d
OSSEC_RANLIB  		=${QUIET_RANLIB}ranlib

ifneq (,$(filter ${USE_INOTIFY},YES auto yes y Y 1))
	DEFINES+=-DINOTIFY_ENABLED
	ifeq (${uname_S},FreeBSD)
		OSSEC_LDFLAGS+=-L/usr/local/lib -I/usr/local/include
		OSSEC_LIBS+=-linotify
		OSSEC_CFLAGS+=-I/usr/local/include
	endif
endif

ifneq (,$(filter ${USE_BIG_ENDIAN},YES yes y Y 1))
	DEFINES+=-DOS_BIG_ENDIAN
endif

ifneq (,$(filter ${USE_PRELUDE},YES auto yes y Y 1))
	DEFINES+=-DPRELUDE_OUTPUT_ENABLED
	OSSEC_LIBS+=-lprelude
	OSSEC_LDFLAGS+=$(shell sh -c '${PRELUDE_CONFIG} --pthread-cflags')
	OSSEC_LIBS+=$(shell sh -c '${PRELUDE_CONFIG} --libs')
endif # USE_PRELUDE

ifneq (,$(filter ${USE_ZEROMQ},YES auto yes y Y 1))
	DEFINES+=-DZEROMQ_OUTPUT_ENABLED
	OSSEC_LIBS+=-lzmq -lczmq
endif # USE_ZEROMQ

ifneq (,$(filter ${USE_GEOIP},YES auto yes y Y 1))
	DEFINES+=-DLIBGEOIP_ENABLED
	OSSEC_LIBS+=-lGeoIP
endif # USE_GEOIP

SYSINFO_LIB+=-lsysinfo

OSSEC_LDFLAGS+=-L${SYSINFO}build/lib

MI :=
PI :=
ifdef DATABASE

	ifeq (${DATABASE},mysql)
		DEFINES+=-DMYSQL_DATABASE_ENABLED

		ifdef MYSQL_CFLAGS
			MI = ${MYSQL_CFLAGS}
		else
			MI := $(shell sh -c '${MY_CONFIG} --include 2>/dev/null || echo ')

			ifeq (${MI},) # BEGIN MI manual detection
				ifneq (,$(wildcard /usr/include/mysql/mysql.h))
					MI="-I/usr/include/mysql/"
				else
					ifneq (,$(wildcard /usr/local/include/mysql/mysql.h))
						MI="-I/usr/local/include/mysql/"
					endif  #
				endif  #MI

			endif
		endif # MYSQL_CFLAGS

		ifdef MYSQL_LIBS
			ML = ${MYSQL_LIBS}
		else
			ML := $(shell sh -c '${MY_CONFIG} --libs 2>/dev/null || echo ')

			ifeq (${ML},)
				ifneq (,$(wildcard /usr/lib/mysql/*))
					ML="-L/usr/lib/mysql"
				else
					ifneq (,$(wildcard /usr/lib64/mysql/*))
						ML="-L/usr/lib64/mysql"
					else
						ifneq (,$(wildcard /usr/local/lib/mysql/*))
							ML="-L/usr/local/lib/mysql"
						else
							ifneq (,$(wildcard /usr/local/lib64/mysql/*))
								ML="-L/usr/local/lib64/mysql"
							endif # local/lib64
						endif # local/lib
					endif # lib54
				endif # lib
			endif
		endif # MYSQL_LIBS

		OSSEC_LIBS+=${ML} -lmysqlclient

	else # DATABASE

		ifeq (${DATABASE}, pgsql)
			DEFINES+=-DPGSQL_DATABASE_ENABLED

			ifneq (${PGSQL_LIBS},)
				PL:=${PGSQL_LIBS}
			else
				PL:=$(shell sh -c '(${PG_CONFIG} --libdir --pkglibdir 2>/dev/null | sed "s/^/-L/g" | xargs ) || echo ')
			endif

			ifneq (${PGSQL_CFLAGS},)
				PI:=${PGSQL_CFLAGS}
			else
				PI:=$(shell sh -c '(${PG_CONFIG} --includedir --pkgincludedir 2>/dev/null | sed "s/^/-I/g" | xargs ) || echo ')
			endif

			# XXX need some basic autodetech stuff here.

			OSSEC_LIBS+=${PL} -lpq

		endif # pgsql
	endif # mysql
endif # DATABASE

####################
#### Target ########
####################

ifndef TARGET
	TARGET=failtarget
endif # TARGET

ifeq (${TARGET},local)
	DEFINES+=-DLOCAL
endif


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

.PHONY: help
help: failtarget
	@echo
	@echo "General options: "
	@echo "   make V=yes                   						Display full compiler messages. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DEBUG=yes               						Build with symbols and without optimization. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DEBUGAD=yes             						Enables extra debugging logging in wazuh-analysisd. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make INSTALLDIR=/path        						Wazuh's installation path. Mandatory when compiling the python interpreter from sources using PYTHON_SOURCE."
	@echo "   make ONEWAY=yes              						Disables manager's ACK towards agent. It allows connecting agents without backward connection from manager. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make CLEANFULL=yes           						Makes the alert mailing subject clear in the format: '<location> - <level> - <description>'. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make RESOURCES_URL           						Set the Wazuh resources URL"
	@echo "   make EXTERNAL_SRC_ONLY=yes   						Combined with 'deps', it downloads only the external source code to be compiled as part of Wazuh building."
	@echo "   make USE_ZEROMQ=yes          						Build with zeromq support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_PRELUDE=yes         						Build with prelude support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_INOTIFY=yes         						Build with inotify support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_BIG_ENDIAN=yes      						Build with big endian support. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_SELINUX=yes         						Build with SELinux policies. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_AUDIT=yes           						Build with audit service support. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_MSGPACK_OPT=yes     						Use default architecture for building msgpack library. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DISABLE_JEMALLOC=yes    						Not to build the JEMalloc library. Allowed values are 1, yes, YES, y, and Y, otherwise, the flag is ignored"
	@echo "   make OFLAGS=-Ox              						Overrides optimization level"
	@echo "   make DISABLE_SYSC=yes        						Not to build the Syscollector module (for unsupported systems). Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DISABLE_CISCAT=yes      						Not to build the CIS-CAT module (for unsupported systems). Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make OPTIMIZE_CPYTHON=yes    						Enable this flag to optimize the python interpreter build, which is performed when used PYTHON_SOURCE. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make PYTHON_SOURCE=yes       						Used along the deps target. Downloads the sources needed to build the python interpreter. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make IMAGE_TRUST_CHECKS=1     					This flag controls the dll and exe files signature verification mechanism. Allowed values are 0 (disabled), 1 (warning only) and 2 (full enforce). The default value is 1."
	@echo "   make CA_NAME="DigiCert Assured ID Root CA" 		This flag controls the CA name used to verify the dll and exe files signature. The default value is DigiCert Assured ID Root CA."
	@echo "   make deps HTTP_REQUEST_BRANCH=main 				Build dependencies for http-request tool from selected branch/tag only if submodule isn't checked out, valid at make deps stage. Allowed values are any existing branch/tag.
	@echo
	@echo "Database options: "
	@echo "   make DATABASE=mysql          Build with MYSQL Support"
	@echo "                                Use MYSQL_CFLAGS adn MYSQL_LIBS to override defaults"
	@echo "   make DATABASE=pgsql          Build with PostgreSQL Support "
	@echo "                                Use PGSQL_CFLAGS adn PGSQL_LIBS to override defaults"
	@echo
	@echo "Geoip support: "
	@echo "   make USE_GEOIP=yes           Build with GeoIP support. Allowed values are auto 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo
	@echo "User options: "
	@echo "   make WAZUH_GROUP=wazuh       Set wazuh group"
	@echo "   make WAZUH_USER=wazuh        Set wazuh user"
	@echo
	@echo "Examples: Client with debugging enabled"
	@echo "   make TARGET=server DEBUG=yes"

.PHONY: settings
settings:
	@echo
	@echo "General settings:"
	@echo "    TARGET:             ${TARGET}"
	@echo "    V:                  ${V}"
	@echo "    DEBUG:              ${DEBUG}"
	@echo "    DEBUGAD             ${DEBUGAD}"
	@echo "    INSTALLDIR:         ${INSTALLDIR}"
	@echo "    DATABASE:           ${DATABASE}"
	@echo "    ONEWAY:             ${ONEWAY}"
	@echo "    CLEANFULL:          ${CLEANFULL}"
	@echo "    RESOURCES_URL:      ${RESOURCES_URL}"
	@echo "    EXTERNAL_SRC_ONLY:  ${EXTERNAL_SRC_ONLY}"
	@echo "    HTTP_REQUEST_BRANCH:${HTTP_REQUEST_BRANCH}"
	@echo "User settings:"
	@echo "    WAZUH_GROUP:        ${WAZUH_GROUP}"
	@echo "    WAZUH_USER:         ${WAZUH_USER}"
	@echo "USE settings:"
	@echo "    USE_ZEROMQ:         ${USE_ZEROMQ}"
	@echo "    USE_GEOIP:          ${USE_GEOIP}"
	@echo "    USE_PRELUDE:        ${USE_PRELUDE}"
	@echo "    USE_INOTIFY:        ${USE_INOTIFY}"
	@echo "    USE_BIG_ENDIAN:     ${USE_BIG_ENDIAN}"
	@echo "    USE_SELINUX:        ${USE_SELINUX}"
	@echo "    USE_AUDIT:          ${USE_AUDIT}"
	@echo "    DISABLE_SYSC:       ${DISABLE_SYSC}"
	@echo "    DISABLE_CISCAT:     ${DISABLE_CISCAT}"
	@echo "    IMAGE_TRUST_CHECKS: ${IMAGE_TRUST_CHECKS}"
	@echo "    CA_NAME:            ${CA_NAME}"
	@echo "Mysql settings:"
	@echo "    includes:           ${MI}"
	@echo "    libs:               ${ML}"
	@echo "Pgsql settings:"
	@echo "    includes:           ${PI}"
	@echo "    libs:               ${PL}"
	@echo "Defines:"
	@echo "    ${DEFINES}"
	@echo "Compiler:"
	@echo "    CFLAGS            ${OSSEC_CFLAGS}"
	@echo "    LDFLAGS           ${OSSEC_LDFLAGS}"
	@echo "    LIBS              ${OSSEC_LIBS}"
	@echo "    CC                ${CC}"
	@echo "    MAKE              ${MAKE}"

BUILD_SERVER+=wazuh-keystore

BUILD_CMAKE_PROJECTS+=build_sysinfo
BUILD_CMAKE_PROJECTS+=build_shared_modules
BUILD_CMAKE_PROJECTS+=build_wazuh_cmake

${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}: ${libstdc++_path}
	cp $< $@
	${STRIP_TOOL} -x $@

${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME}: ${libgcc_s_path}
	cp $< $@
	${STRIP_TOOL} -x $@

.PHONY: server 

ifeq (${MAKECMDGOALS},server)
$(error Do not use 'server' directly, use 'TARGET=server')
endif
server: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}
	${MAKE} ${BUILD_SERVER}

ifneq (,$(filter ${USE_SELINUX},YES yes y Y 1))
server: selinux
endif

selinux: $(SELINUX_POLICY)

$(SELINUX_POLICY): $(SELINUX_MODULE)
	semodule_package -o $@ -m $?

$(SELINUX_MODULE): $(SELINUX_ENFORCEMENT)
	checkmodule -M -m -o $@ $?

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
FLATBUFFERS_LIB = $(EXTERNAL_FLATBUFFERS)build/libflatbuffers.a
LZMA_LIB = $(EXTERNAL_LZMA)build/liblzma.a
LUA_LIB = ${EXTERNAL_LUA}install/lib/liblua.a

EXTERNAL_LIBS := $(JSON_LIB) $(ZLIB_LIB) $(OPENSSL_LIB) $(CRYPTO_LIB) $(SQLITE_LIB) $(LIBYAML_LIB) $(LIBPCRE2_LIB) $(LIBCURL_LIB) $(LZMA_LIB) $(MINIZIP_LIB) $(MSGPACK_LIB) $(LIBFFI_LIB) $(BZIP2_LIB)

# Adding libraries only for server
EXTERNAL_LIBS_NO_WHOLE += $(ROCKSDB_LIB) $(FLATBUFFERS_LIB)

ifeq (${uname_S},Linux)
EXTERNAL_LIBS +=  ${LUA_LIB} ${RPM_LIB} ${POPT_LIB}
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
EXTERNAL_LIBS += ${AUDIT_LIB}
endif
EXTERNAL_LIBS += $(PROCPS_LIB) $(LIBALPM_LIB) $(LIBARCHIVE_LIB)
endif


.PHONY: external test_external
external: test_external $(EXTERNAL_LIBS) $(JEMALLOC_LIB)

ifneq (,$(filter ${TEST},YES yes y Y 1))
external: build_gtest build_benchmark
endif

ifeq (${TARGET},server)
external: $(ROCKSDB_LIB)
endif

ifneq (,$(wildcard ${EXTERNAL_CPYTHON}))
external: build_python
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
	cd ${EXTERNAL_OPENSSL} && ./config $(OPENSSL_FLAGS) && ${MAKE} build_libs

### rocks db ###

${ROCKSDB_LIB}:
	cd $(EXTERNAL_ROCKSDB) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DWITH_GFLAGS=0 -DWITH_TESTS=0 -DWITH_BENCHMARK_TOOLS=0 -DWITH_TOOLS=0 -DUSE_RTTI=1 -DROCKSDB_BUILD_SHARED=1 -DWITH_BZ2=1 -DBZIP2_INCLUDE_DIR=$(realpath $(EXTERNAL_BZIP2)) -DBZIP2_LIBRARIES=$(realpath $(BZIP2_LIB)) -DCMAKE_POSITION_INDEPENDENT_CODE=1 -DWITH_ALL_TESTS=0 -DWITH_RUNTIME_DEBUG=0 -DWITH_TRACE_TOOLS=0 -DPORTABLE=1 && ${MAKE}

### flatbuffers ###
${FLATBUFFERS_LIB}:
	cd $(EXTERNAL_FLATBUFFERS) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=0 -DFLATBUFFERS_INSTALL=0 -DCMAKE_POSITION_INDEPENDENT_CODE=1 && ${MAKE}

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

#### zlib ##########

$(ZLIB_LIB):
	cd ${EXTERNAL_ZLIB} && CFLAGS=-fPIC ./configure && ${MAKE} libz.a

ZLIB_INCLUDE=-I./${EXTERNAL_ZLIB}

os_zlib_c := os_zlib/os_zlib.c
os_zlib_o := $(os_zlib_c:.c=.o)

os_zlib/%.o: os_zlib/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@

#### minizip ##########

$(MINIZIP_LIB): $(ZLIB_LIB)
	cd ${EXTERNAL_ZLIB}/contrib/minizip && ${OSSEC_CC} -fPIC -c unzip.c ioapi.c -I../../ && ar rcs libminizip.a unzip.o ioapi.o

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
	cd $(EXTERNAL_LIBYAML) && CFLAGS=-fPIC ./configure --enable-static=yes --enable-shared=no

#### curl ##########

${LIBCURL_LIB}: $(EXTERNAL_CURL)Makefile
	${MAKE} -C $(EXTERNAL_CURL)lib

$(EXTERNAL_CURL)Makefile: $(OPENSSL_LIB)
ifeq (${uname_S},Linux)
ifneq (,$(filter ${uname_M},aarch64 ppc64le))
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-ldl -lpthread" ./configure --build=${uname_M}-unknown-linux-gnu --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" --disable-ldap --without-libidn2 --without-libpsl --without-brotli --without-nghttp2 --without-zstd
else
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-ldl -lpthread" ./configure --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" --disable-ldap --without-libidn2 --without-libpsl --without-brotli --without-nghttp2 --without-zstd
endif
else
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-lpthread" ./configure --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" --disable-ldap --without-libidn2 --without-brotli --without-nghttp2 --without-librtmp --without-zstd
endif


#### procps #########

PROCPS_INCLUDE=-I./${EXTERNAL_PROCPS}

procps_c := $(wildcard ${EXTERNAL_PROCPS}*.c)
procps_o := $(procps_c:.c=.o)

${EXTERNAL_PROCPS}%.o: ${EXTERNAL_PROCPS}%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

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

ifeq (${uname_S},Linux)
${LIBARCHIVE_LIB}: $(EXTERNAL_LIBARCHIVE)Makefile
	 ${MAKE} -C $(EXTERNAL_LIBARCHIVE)

$(EXTERNAL_LIBARCHIVE)Makefile:
	cd ${EXTERNAL_LIBARCHIVE} && CPPFLAGS=-fPIC ./configure --disable-acl --without-expat --without-iconv --without-xml2 --without-lz4 --without-lzma --without-zstd --without-bz2lib --without-openssl --without-libb2
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

msgpack_c := $(wildcard ${EXTERNAL_MSGPACK}src/*.c)
msgpack_o := $(msgpack_c:.c=.o)

${EXTERNAL_MSGPACK}src/%.o: ${EXTERNAL_MSGPACK}src/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${MSGPACK_ARCH} -fPIC -c $^ -o $@

$(MSGPACK_LIB): ${msgpack_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### PCRE2 lib #########



$(LIBPCRE2_LIB):
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC ./configure --enable-jit=auto --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}

### popt lib ###

POPT_BUILD_DIR = $(EXTERNAL_POPT)build/

$(POPT_LIB): $(POPT_BUILD_DIR)Makefile
	 $(MAKE) -C $(POPT_BUILD_DIR)
$(POPT_BUILD_DIR)Makefile:
	mkdir -p $(POPT_BUILD_DIR) && cd $(POPT_BUILD_DIR) && cmake ..

### lua lib ###
	cd ${EXTERNAL_LUA} && make posix MYCFLAGS='-fPIC' && make local


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

################################
#### External dependencies  ####
################################

TAR := tar -xf
GUNZIP := gunzip
GZIP := gzip
CURL := curl -so
DEPS_VERSION = 30
RESOURCES_URL_BASE := https://packages.wazuh.com/deps/
RESOURCES_URL := $(RESOURCES_URL_BASE)$(DEPS_VERSION)
CPYTHON := cpython
PYTHON_SOURCE := no

ifneq (,$(filter ${uname_S},Linux))
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
ifeq (${cpu_arch},ppc64le)
	PRECOMPILED_ARCH := /ppc64le
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
endif
endif

ifeq (,$(filter ${EXTERNAL_SRC_ONLY},YES yes y Y 1))
# If EXTERNAL_SRC_ONLY=YES is not defined, lets look for the precompiled lib
PRECOMPILED_RES := $(PRECOMPILED_OS)$(PRECOMPILED_ARCH)
endif

EXTERNAL_RES := cJSON curl libdb libffi libyaml openssl procps sqlite zlib audit-userspace msgpack bzip2 nlohmann googletest libpcre2 libplist pacman libarchive popt lua rpm rocksdb lzma cpp-httplib benchmark $(CPYTHON) jemalloc flatbuffers

EXTERNAL_DIR := $(EXTERNAL_RES:%=external/%)
EXTERNAL_TAR := $(EXTERNAL_RES:%=external/%.tar.gz)

# Shared tools like dependencies
SHARED_RES := http-request
SHARED_TAR := $(SHARED_RES:%=shared_modules/%.tar.gz)

.PHONY: deps
deps: $(EXTERNAL_TAR) $(SHARED_TAR)

external/$(CPYTHON).tar.gz:
# Python interpreter
ifeq (,$(filter ${PYTHON_SOURCE},YES yes y Y 1))
ifneq (,$(PRECOMPILED_RES))
external/$(CPYTHON).tar.gz: external-precompiled/$(CPYTHON).tar.gz
	test -e $(patsubst %.gz,%,$@) ||\
	($(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@) &&\
	cd external && $(GUNZIP) $(patsubst external/%,%,$@) && $(TAR) $(patsubst external/%.gz,%,$@) && rm $(patsubst external/%.gz,%,$@))
	test -d $(patsubst %.tar.gz,%,$@) || (cd external && $(GZIP) $(patsubst external/%.gz,%,$@))

external-precompiled/$(CPYTHON).tar.gz:
	-$(CURL) external/$(patsubst external-precompiled/%,%,$@) $(RESOURCES_URL)/libraries/$(PRECOMPILED_RES)/$(patsubst external-precompiled/%,%,$@) || true
	-cd external && test -e $(patsubst external-precompiled/%,%,$@) && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
else
external/$(CPYTHON).tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif
else
external/$(CPYTHON).tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif

ifeq (${uname_S},HP-UX)
# nlohmann library
RESOURCES_URL_BASE_NLOHMANN=$(subst https://,http://,$(RESOURCES_URL_BASE))
ifeq ($(findstring $(RESOURCES_URL_BASE_NLOHMANN),$(RESOURCES_URL)),$(RESOURCES_URL_BASE_NLOHMANN))
DEPS_VERSION_NLOHMANN_REQUESTED=$(subst $(RESOURCES_URL_BASE_NLOHMANN),,$(RESOURCES_URL))
DEPS_VERSION_NLOHMANN_MAX=21
ifeq ($(shell test $(DEPS_VERSION_NLOHMANN_REQUESTED) -gt $(DEPS_VERSION_NLOHMANN_MAX); echo $$?),0)
DEPS_VERSION_NLOHMANN=$(DEPS_VERSION_NLOHMANN_MAX)
else
DEPS_VERSION_NLOHMANN=$(DEPS_VERSION_NLOHMANN_REQUESTED)
endif
RESOURCES_URL_NLOHMANN=$(RESOURCES_URL_BASE_NLOHMANN)$(DEPS_VERSION_NLOHMANN)
ifneq (,$(PRECOMPILED_RES))
external/nlohmann.tar.gz: external-precompiled/nlohmann.tar.gz
	test -d $(patsubst %.tar.gz,%,$@) ||\
	($(CURL) $@ $(RESOURCES_URL_NLOHMANN)/libraries/sources/$(patsubst external/%,%,$@) &&\
	cd external && $(GUNZIP) $(patsubst external/%,%,$@) && $(TAR) $(patsubst external/%.gz,%,$@) && rm $(patsubst external/%.gz,%,$@))

external-precompiled/nlohmann.tar.gz:
	-$(CURL) external/$(patsubst external-precompiled/%,%,$@) $(RESOURCES_URL_NLOHMANN)/libraries/$(PRECOMPILED_RES)/$(patsubst external-precompiled/%,%,$@) || true
	-cd external && test -e $(patsubst external-precompiled/%,%,$@) && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	-cd external && test -e $(patsubst external-precompiled/%.gz,%,$@) && $(TAR) $(patsubst external-precompiled/%.gz,%,$@) || true
	-test -e external/$(patsubst external-precompiled/%.gz,%,$@) && rm external/$(patsubst external-precompiled/%.gz,%,$@) || true
else
external/nlohmann.tar.gz:
	$(CURL) $@ $(RESOURCES_URL_NLOHMANN)/libraries/sources/$(patsubst external/%,%,$@)
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif
endif
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
	-cd external && test -e $(patsubst external-precompiled/%,%,$@) && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	-cd external && test -e $(patsubst external-precompiled/%.gz,%,$@) && $(TAR) $(patsubst external-precompiled/%.gz,%,$@) || true
	-test -e external/$(patsubst external-precompiled/%.gz,%,$@) && rm external/$(patsubst external-precompiled/%.gz,%,$@) || true
endif

# Shared tools
HTTP_REQUEST_URL := https://github.com/wazuh/wazuh-http-request/tarball/$(HTTP_REQUEST_BRANCH)

shared_modules/http-request.tar.gz:
	find $(patsubst %.tar.gz,%,$@) -type f -exec false {} + &&\
	((test -e $(patsubst %.gz,%,$@) || $(CURL) $@ -L $(HTTP_REQUEST_URL)) &&\
	($(GUNZIP) $@ || (rm -f $@ && echo "Error decompressing $@ maybe wrong branch was supplied!" && false)) &&\
	$(TAR) $(patsubst %.gz,%,$@) --strip-components=1 -C $(patsubst %.tar.gz,%,$@) &&\
	rm $(patsubst %.gz,%,$@)) || true

####################
#### OSSEC Libs ####
####################

WAZUHEXT_LIB = libwazuhext.$(SHARED)
WAZUH_LIB = libwazuhshared.$(SHARED)
BUILD_LIBS = libwazuh.a $(WAZUHEXT_LIB)

$(BUILD_SERVER) $(BUILD_AGENT) : $(BUILD_LIBS)

#### os_xml ########

os_xml_c := $(wildcard os_xml/*.c)
os_xml_o := $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

#### Shared ##########
# Unit tests wrappers

wrappers_common_c := $(wildcard unit_tests/wrappers/*.c)
wrappers_common_o := $(wrappers_common_c:.c=.o)

wrappers_externals_c := $(wildcard unit_tests/wrappers/externals/*.c)
wrappers_externals_o := $(wrappers_externals_c:.c=.o)

wrappers_externals_audit_c := $(wildcard unit_tests/wrappers/externals/audit/*.c)
wrappers_externals_audit_o := $(wrappers_externals_audit_c:.c=.o)

wrappers_externals_bzip2_c := $(wildcard unit_tests/wrappers/externals/bzip2/*.c)
wrappers_externals_bzip2_o := $(wrappers_externals_bzip2_c:.c=.o)

wrappers_externals_zlib_c := $(wildcard unit_tests/wrappers/externals/zlib/*.c)
wrappers_externals_zlib_o := $(wrappers_externals_zlib_c:.c=.o)

wrappers_externals_cJSON_c := $(wildcard unit_tests/wrappers/externals/cJSON/*.c)
wrappers_externals_cJSON_o := $(wrappers_externals_cJSON_c:.c=.o)

wrappers_externals_openssl_c := $(wildcard unit_tests/wrappers/externals/openssl/*.c)
wrappers_externals_openssl_o := $(wrappers_externals_openssl_c:.c=.o)

wrappers_externals_procpc_c := $(wildcard unit_tests/wrappers/externals/procpc/*.c)
wrappers_externals_procpc_o := $(wrappers_externals_procpc_c:.c=.o)

wrappers_externals_sqlite_c := $(wildcard unit_tests/wrappers/externals/sqlite/*.c)
wrappers_externals_sqlite_o := $(wrappers_externals_sqlite_c:.c=.o)

wrappers_externals_pcre2_c := $(wildcard unit_tests/wrappers/externals/pcre2/*.c)
wrappers_externals_pcre2_o := $(wrappers_externals_pcre2_c:.c=.o)

wrappers_libc_c := $(wildcard unit_tests/wrappers/libc/*.c)
wrappers_libc_o := $(wrappers_libc_c:.c=.o)

wrappers_linux_c := $(wildcard unit_tests/wrappers/linux/*.c)
wrappers_linux_o := $(wrappers_linux_c:.c=.o)

wrappers_posix_c := $(wildcard unit_tests/wrappers/posix/*.c)
wrappers_posix_o := $(wrappers_posix_c:.c=.o)

wrappers_wazuh_c := $(wildcard unit_tests/wrappers/wazuh/*.c)
wrappers_wazuh_o := $(wrappers_wazuh_c:.c=.o)

wrappers_wazuh_os_crypto_c := $(wildcard unit_tests/wrappers/wazuh/os_crypto/*.c)
wrappers_wazuh_os_crypto_o := $(wrappers_wazuh_os_crypto_c:.c=.o)

wrappers_data_provider_c := $(wildcard unit_tests/wrappers/wazuh/data_provider/*.c)
wrappers_data_provider_o := $(wrappers_data_provider_c:.c=.o)

wrappers_wazuh_shared_modules_c := $(wildcard unit_tests/wrappers/wazuh/shared_modules/*.c)
wrappers_wazuh_shared_modules_o := $(wrappers_wazuh_shared_modules_c:.c=.o)

ifneq (,$(filter ${TEST},YES yes y Y 1))
	OSSEC_CFLAGS+=${CFLAGS_TEST}
	OSSEC_LDFLAGS+=${CFLAGS_TEST}
	AR_LDFLAGS+=${CFLAGS_TEST}
	OSSEC_LIBS+=${LIBS_TEST}

	UNIT_TEST_WRAPPERS+=${wrappers_externals_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_bzip2_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_zlib_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_cJSON_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_openssl_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_sqlite_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_pcre2_o}
	UNIT_TEST_WRAPPERS+=${wrappers_libc_o}
	UNIT_TEST_WRAPPERS+=${wrappers_posix_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_crypto_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_regex_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_xml_o}
	UNIT_TEST_WRAPPERS+=${wrappers_data_provider_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_audit_o}
	UNIT_TEST_WRAPPERS+=${wrappers_externals_procpc_o}
	UNIT_TEST_WRAPPERS+=${wrappers_linux_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_shared_modules_o}
	
endif #TEST

#### Config ##########

build_shared_modules: $(WAZUHEXT_LIB)
	cd ${DBSYNC} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${DBSYNC_TEST} ${SHARED_MODULES_RELEASE_TYPE} .. && ${MAKE}
	cd ${RSYNC} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${RSYNC_TEST} ${SHARED_MODULES_RELEASE_TYPE} .. && ${MAKE}

#### Sysinfo ##
build_sysinfo: $(WAZUHEXT_LIB)
	cd ${SYSINFO} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${SYSINFO_OS} ${SYSINFO_TEST} ${SYSINFO_RELEASE_TYPE} .. && ${MAKE}

#### Wazuh cmake ###
build_wazuh_cmake: $(WAZUHEXT_LIB) $(EXTERNAL_LIBS_NO_WHOLE) 
	mkdir -p build && cd build && cmake .. -DTARGET=${TARGET} ${CMAKE_OPTS} ${WAZUH_RELEASE_TYPE} ${WAZUH_TEST} && ${MAKE}

#### crypto ##########

crypto_blowfish_c := os_crypto/blowfish/bf_op.c
crypto_blowfish_o := $(crypto_blowfish_c:.c=.o)

os_crypto/blowfish/%.o: os_crypto/blowfish/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_md5_c := os_crypto/md5/md5_op.c
crypto_md5_o := $(crypto_md5_c:.c=.o)

os_crypto/md5/%.o: os_crypto/md5/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_sha256_c := os_crypto/sha256/sha256_op.c
crypto_sha256_o := $(crypto_sha256_c:.c=.o)

os_crypto/sha256/%.o: os_crypto/sha256/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_sha512_c := os_crypto/sha512/sha512_op.c
crypto_sha512_o := $(crypto_sha512_c:.c=.o)

os_crypto/sha512/%.o: os_crypto/sha512/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_aes_c := os_crypto/aes/aes_op.c
crypto_aes_o := $(crypto_aes_c:.c=.o)

os_crypto/aes/%.o: os_crypto/aes/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_o := ${crypto_blowfish_o} \
					 ${crypto_md5_o} \
					 ${crypto_sha256_o} \
					 ${crypto_sha512_o} \
					 ${crypto_aes_o} \

#### libwazuh #########

libwazuh.a: ${crypto_o} ${os_zlib_o} ${UNIT_TEST_WRAPPERS}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

### libwazuhext #########
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}

### libwazuhshared.so #########
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}

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
WLIBPYTHON=libpython3.10.so.1.0

ifneq (,$(filter ${OPTIMIZE_CPYTHON},YES yes y Y 1))
CPYTHON_FLAGS=--enable-optimizations
endif

wpython: install_dependencies install_framework install_api install_comms_api install_mitre

build_python:
ifeq (,${INSTALLDIR})
	$(error INSTALLDIR undefined. Run "${MAKE} TARGET=server INSTALLDIR=/path" to build python from sources)
endif

ifeq (,$(wildcard ${EXTERNAL_CPYTHON}/python))
	export WPATH_LIB="'\$$\$$ORIGIN/../../../lib'" && export SOURCE_PATH=${ROUTE_PATH} && export WAZUH_FFI_PATH=${EXTERNAL_LIBFFI} && export LD_LIBRARY_PATH=${ROUTE_PATH} && cd ${EXTERNAL_CPYTHON} && ./configure --prefix="${WPYTHON_DIR}" --libdir="${WPYTHON_DIR}/lib" --enable-shared --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" -L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'\$$\$$ORIGIN/../../../lib',--disable-new-dtags" CPPFLAGS="-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}" $(CPYTHON_FLAGS) && ${MAKE}
endif

build_python: $(WAZUHEXT_LIB)

install_python:
ifneq (,$(wildcard ${EXTERNAL_CPYTHON}))
	cd ${EXTERNAL_CPYTHON} && export WPATH_LIB=${INSTALLDIR}/lib && export SOURCE_PATH=${ROUTE_PATH} && export WAZUH_FFI_PATH=${EXTERNAL_LIBFFI} && ${MAKE} install
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

install_comms_api: install_python
	cd ../apis/comms_api && ${WPYTHON_DIR}/bin/python3 -m pip install . --use-pep517 --prefix=${WPYTHON_DIR} && rm -rf build/

install_mitre: install_python
	cd ../tools/mitre && ${WPYTHON_DIR}/bin/python3 mitredb.py -d ${INSTALLDIR}/var/db/mitre.db

####################
#### test ##########
####################
CFLAGS_TEST=-g -O0 --coverage -DWAZUH_UNIT_TESTING
# Use sanitizers only on linux
ifeq (${uname_S},Linux)
CFLAGS_TEST+= -fsanitize=address -fsanitize=undefined
endif

LIBS_TEST=-lcmocka

unit_tests/wrappers/%.o: unit_tests/wrappers/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/%.o: unit_tests/wrappers/externals/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/audit/%.o: unit_tests/wrappers/externals/audit/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/bzip2/%.o: unit_tests/wrappers/externals/bzip2/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/cJSON/%.o: unit_tests/wrappers/externals/cJSON/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/openssl/%.o: unit_tests/wrappers/externals/openssl/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/procpc/%.o: unit_tests/wrappers/externals/procpc/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/externals/sqlite/%.o: unit_tests/wrappers/externals/sqlite/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/libc/%.o: unit_tests/wrappers/libc/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/linux/%.o: unit_tests/wrappers/linux/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/posix/%.o: unit_tests/wrappers/posix/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/%.o: unit_tests/wrappers/wazuh/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_crypto/%.o: unit_tests/wrappers/wazuh/os_crypto/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_regex/%.o: unit_tests/wrappers/wazuh/os_regex/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

.PHONY: test

###################
#### Rule Tests ###
###################

test-rules:
	( cd ../ruleset/testing && sudo python runtests.py)

####################
#### Clean #########
####################

clean: clean-test clean-internals clean-external clean-framework clean-config

clean-test:
	rm -Rf coverage-report/
	find . -name "*.gcno" -exec rm {} \;
	find . -name "*.gcda" -exec rm {} \;

clean-external: clean-wpython
ifneq ($(wildcard external/*/*),)
	rm -f ${cjson_o} $(EXTERNAL_JSON)libcjson.*
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f Makefile.in distclean
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
	rm -rf $(EXTERNAL_FLATBUFFERS)build
	rm -rf $(EXTERNAL_LZMA)build
	-cd ${EXTERNAL_LIBPLIST} && ${MAKE} clean && rm -rf bin/*
	-cd ${EXTERNAL_LIBPCRE2} && ${MAKE} distclean && rm -rf include/*
	rm -rf ${POPT_BUILD_DIR}
	rm -rf ${RPM_BUILD_DIR}
	-cd ${EXTERNAL_LUA} && ${MAKE} clean && rm -rf install/*

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
	rm -rf $(EXTERNAL_DIR) $(EXTERNAL_TAR) shared_modules/http-request/* shared_modules/http-request/.??*

clean-internals: clean-unit-tests
	rm -f $(BUILD_SERVER)
	rm -f $(BUILD_LIBS)
	rm -f ${os_zlib_o}
	rm -f ${os_xml_o}
	rm -f ${os_regex_o}
	rm -f ${crypto_o}
	rm -f ${SELINUX_MODULE}
	rm -f ${SELINUX_POLICY}
	rm -f $(WAZUH_LIB)
	rm -rf $(DBSYNC)build
	rm -rf $(RSYNC)build
	rm -rf $(SHARED_MODULES)utils/flatbuffers/include/
	rm -rf $(wildcard $(VULNERABILITY_SCANNER)include/*_generated.h)
	rm -rf $(SYSINFO)build
	rm -rf ${SHARED_MODULES}http-request/build
	rm -rf build
	rm -rf libwazuhext
	rm -rf libstdc++.so.6
	rm -rf libgcc_s.so.1
	rm -f libwazuh.a


clean-unit-tests:
	rm -f ${wrappers_externals_o}
	rm -f ${wrappers_externals_audit_o}
	rm -f ${wrappers_externals_bzip2_o}
	rm -f ${wrappers_externals_zlib_o}
	rm -f ${wrappers_externals_cJSON_o}
	rm -f ${wrappers_externals_openssl_o}
	rm -f ${wrappers_externals_procpc_o}
	rm -f ${wrappers_externals_sqlite_o}
	rm -f ${wrappers_externals_pcre2_o}
	rm -f ${wrappers_libc_o}
	rm -f ${wrappers_linux_o}
	rm -f ${wrappers_posix_o}
	rm -f ${wrappers_wazuh_o}
	rm -f ${wrappers_wazuh_os_crypto_o}
	rm -f ${wrappers_wazuh_os_regex_o}
	rm -f ${wrappers_wazuh_os_xml_o}
	rm -f ${wrappers_data_provider_o}

clean-framework:
	${MAKE} -C ../framework clean

clean-config:
	rm -f ../etc/ossec.mc
	rm -f Config.OS
