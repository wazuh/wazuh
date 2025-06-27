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


ifeq (${TARGET}, winagent)
WAZUH_LIB_OUTPUT_PATH := win32/
STRIP_TOOL := i686-w64-mingw32-strip
DLLTOOL := i686-w64-mingw32-dlltool
libstdc++_path := $(shell sh -c 'i686-w64-mingw32-g++-posix --print-file-name=libstdc++-6.dll 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++-6.dll
libgcc_s_path := $(shell sh -c 'i686-w64-mingw32-g++-posix --print-file-name=libgcc_s_dw2-1.dll 2>/dev/null || echo not')
LIBGCC_S_NAME := libgcc_s_dw2-1.dll
else
ifeq (${uname_S},AIX)
libstdc++_path_temp := $(shell sh -c 'g++ --print-file-name=libstdc++.a 2>/dev/null || echo not')
libgcc_s_path_temp := $(shell sh -c 'g++ --print-file-name=libgcc_s.a 2>/dev/null || echo not')
libstdc++_path=$(subst libstdc++.a,pthread/libstdc++.a,$(libstdc++_path_temp))
libgcc_s_path=$(subst libgcc_s.a,pthread/libgcc_s.a,$(libgcc_s_path_temp))
LIBSTDCPP_NAME := libstdc++.a
LIBGCC_S_NAME := libgcc_s.a
else
libstdc++_path := $(shell sh -c 'g++ --print-file-name=libstdc++.so.6 2>/dev/null || echo not')
libgcc_s_path := $(shell sh -c 'g++ --print-file-name=libgcc_s.so.1 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++.so.6
LIBGCC_S_NAME := libgcc_s.so.1
endif
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
CHECK_CENTOS5 := $(shell sh -c 'grep "CentOS release 5." /etc/redhat-release 2>&1 > /dev/null && echo YES || echo not')
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
EXTERNAL_FLATBUFFERS=external/flatbuffers/
EXTERNAL_LZMA=external/lzma/
EXTERNAL_LUA=external/lua/
EXTERNAL_LIBPCRE2=external/libpcre2/
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
WAZUH_MODULES=wazuh_modules/
DBSYNC=${SHARED_MODULES}dbsync/
RSYNC=${SHARED_MODULES}rsync/
SYSCOLLECTOR=wazuh_modules/syscollector/
ROUTER=shared_modules/router/
CONTENT_MANAGER=shared_modules/content_manager/
VULNERABILITY_SCANNER=wazuh_modules/vulnerability_scanner/
INVENTORY_HARVESTER=wazuh_modules/inventory_harvester/
SYSINFO=data_provider/
SYSCHECK=syscheckd/
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
HTTP_REQUEST_BRANCH?=75384783d339a817b8d8f13f778051a878d642a6

ifeq (${TARGET},winagent)
CMAKE_OPTS=-DCMAKE_SYSTEM_NAME=Windows -DCMAKE_C_COMPILER=${MING_BASE}${CC} -DCMAKE_CXX_COMPILER=${MING_BASE}${CXX}
WIN_CMAKE_RULES+=win32/sysinfo
WIN_CMAKE_RULES+=win32/shared_modules
WIN_RESOURCE_OBJ=-DRESOURCE_OBJ=win32/version-dll.o
ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
WIN_CMAKE_RULES+=win32/syscollector
endif
endif

ifeq (${uname_S},Darwin)
SYSINFO_OS=-DCMAKE_SYSTEM_NAME=Darwin
endif

ifneq (,$(filter ${TEST},YES yes y Y 1))
SYSCHECK_TEST=-DUNIT_TEST=ON #--coverage
DBSYNC_TEST=-DUNIT_TEST=ON #--coverage
RSYNC_TEST=-DUNIT_TEST=ON #--coverage
SYSCOLLECTOR_TEST=-DUNIT_TEST=ON #--coverage
SYSINFO_TEST=-DUNIT_TEST=ON #--coverage
WAZUH_TEST=-DUNIT_TEST=ON #--coverage
endif
ifneq (,$(filter ${DEBUG},YES yes y Y 1))
SHARED_MODULES_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
GTEST_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
SYSCOLLECTOR_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
SYSINFO_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
SYSCHECK_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
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

ifneq (${TARGET},winagent)
		DEFINES+=-D${uname_S}
ifeq (${uname_S},Linux)
		PRECOMPILED_OS:=linux
		DEFINES+=-DINOTIFY_ENABLED -D_XOPEN_SOURCE=600 -D_GNU_SOURCE
ifeq (${CHECK_CENTOS5},YES)
		OSSEC_CFLAGS+=-pthread
else
		OSSEC_CFLAGS+=-pthread -I${EXTERNAL_PACMAN}lib/libalpm/ -I${EXTERNAL_LIBARCHIVE}libarchive
endif
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../../lib'
ifeq (${CHECK_ALPINE},YES)
		OSSEC_LIBS+=-lintl
		DEFINES+=-DALPINE
endif
		OSSEC_LIBS+=-lrt -ldl -lm
		OSSEC_LDFLAGS+=-pthread -lrt -ldl
		AR_LDFLAGS+=-pthread -lrt -ldl
		OSSEC_CFLAGS+=-Wl,--start-group
		USE_AUDIT=yes
		CC=gcc
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
		OSSEC_CFLAGS+=-I$(EXTERNAL_AUDIT)lib
endif
ifeq (${CHECK_ARCHLINUX},YES)
		ARCH_FLAGS+=-lnghttp2 -lbrotlidec -lpsl
		OSSEC_LDFLAGS+=-lnghttp2 -lbrotlidec -lpsl
		AR_LDFLAGS+=-lnghttp2 -lbrotlidec -lpsl
endif
else
ifeq (${uname_S},AIX)
		DEFINES+=-DAIX -D__unix
		DEFINES+=-DHIGHFIRST
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread -L./lib
ifeq ($(INSTALLDIR),)
	INSTALLDIR = /var/ossec
endif
		CMAKE_OPTS+=-DINSTALL_PREFIX=${INSTALLDIR}
ifeq (${uname_S},AIX)
		OSSEC_LDFLAGS+='-Wl,-blibpath:${INSTALLDIR}/lib:/opt/freeware/lib:/usr/lib:/lib'
else
		OSSEC_LDFLAGS+='-Wl,-blibpath:${INSTALLDIR}/lib:/usr/lib:/lib'
endif
		AR_LDFLAGS+=-pthread
		AR_LDFLAGS+='-Wl,-blibpath:${INSTALLDIR}/lib:/usr/lib:/lib'
		PATH:=${PATH}:/usr/vac/bin
		CC=gcc
		PRECOMPILED_OS:=aix
else
ifeq (${uname_S},SunOS)
SOLARIS_CMAKE_OPTS=-DSOLARIS=ON
PRECOMPILED_OS:=solaris
ifneq ($(uname_R),5.10)
		DEFINES+=-DSUN_MAJOR_VERSION=$(word 1, $(subst ., ,$(uname_V)))
		DEFINES+=-DSUN_MINOR_VERSION=$(word 2, $(subst ., ,$(uname_V)))
else
		DEFINES+=-DSUN_MAJOR_VERSION=10
		DEFINES+=-DSUN_MINOR_VERSION=0
endif
		DEFINES+=-DSOLARIS
		DEFINES+=-DHIGHFIRST
		DEFINES+=-D_REENTRANT
ifneq ($(uname_R),5.10)
		OSSEC_LDFLAGS+=-z relax=secadj
		AR_LDFLAGS+=-z relax=secadj
else
		OSSEC_CFLAGS+=-DMSGPACK_ZONE_ALIGN=8
endif
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../../lib'
		OSSEC_LIBS+=-lsocket -lnsl -lresolv -lrt -lpthread -lm
		PATH:=${PATH}:/usr/ccs/bin:/usr/xpg4/bin:/opt/csw/gcc3/bin:/opt/csw/bin:/usr/sfw/bin
		CC=gcc
#		This is necessary in order to compile libcurl
		NM=gnm
		uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')
else
ifeq (${uname_S},Darwin)
	DEFINES+=-DDarwin
	DEFINES+=-DHIGHFIRST
	OSSEC_CFLAGS+=-pthread
	OSSEC_LDFLAGS+=-pthread
	OSSEC_LDFLAGS+=-Xlinker -rpath -Xlinker "@executable_path/../lib"
	AR_LDFLAGS+=-pthread
	AR_LDFLAGS+=-Xlinker -rpath -Xlinker "@executable_path/../../lib"
	SHARED=dylib
	OSSEC_LIBS+=-framework Security -framework CoreFoundation -framework SystemConfiguration
	PRECOMPILED_OS:=darwin
else
ifeq (${uname_S},FreeBSD)
		DEFINES+=-DFreeBSD
		OSSEC_CFLAGS+=-pthread -I/usr/local/include
		OSSEC_LDFLAGS+=-pthread
		OSSEC_LDFLAGS+=-L/usr/local/lib
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+=-pthread
		AR_LDFLAGS+=-L/usr/local/lib
		AR_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../../lib'
		PRECOMPILED_OS:=freebsd
else
ifeq (${uname_S},NetBSD)
		DEFINES+=-DNetBSD
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+=-pthread
		AR_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../../lib'
		PRECOMPILED_OS:=netbsd
else
ifeq (${uname_S},OpenBSD)
		DEFINES+=-DOpenBSD
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		OSSEC_LDFLAGS+=-L/usr/local/lib
		OSSEC_LDFLAGS+=-Wl,-zorigin '-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+=-pthread
		AR_LDFLAGS+=-L/usr/local/lib
		AR_LDFLAGS+=-Wl,-zorigin '-Wl,-rpath,$$ORIGIN/../../lib'
		PRECOMPILED_OS:=openbsd
else
ifeq (${uname_S},HP-UX)
		DEFINES+=-DHPUX
		DEFINES+=-D_XOPEN_SOURCE_EXTENDED
		DEFINES+=-DHIGHFIRST
		DEFINES+=-DOS_BIG_ENDIAN
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-lrt -pthread -L. -lwazuhext
		AR_LDFLAGS+=-lrt -pthread -L. -lwazuhext -lwazuhshared
ifeq ($(INSTALLDIR),)
	INSTALLDIR = /var/ossec
endif
		CMAKE_OPTS+=-DINSTALL_PREFIX=${INSTALLDIR}
		OSSEC_LDFLAGS+='-Wl,+b,${INSTALLDIR}/lib'
		AR_LDFLAGS+='-Wl,+b,${INSTALLDIR}/lib'
		OSSEC_CFLAGS+=-pthread
		PATH:=${PATH}:/usr/local/bin
		CC=gcc
		INSTALL=/usr/local/coreutils/bin/install
		PRECOMPILED_OS:=hpux
else
	    # Unknow platform
endif # HPUX
endif # OpenBSD
endif # NetBSD
endif # FreeBSD
endif # Darwin
endif # SunOS
endif # AIX
endif # Linux
else
	    # There is a bug in the delay load mechanism for MinGW 32-bits executables (https://www.sourceware.org/bugzilla/show_bug.cgi?id=22676)
		# The workaround is to remove the __declspec(dllimport) from the function declaration in the executables (https://www.sourceware.org/bugzilla/show_bug.cgi?id=14339)
		SHARED=dll
		DEFINES_EVENTCHANNEL=-D_WIN32_WINNT=0x600
		# We link against a patched libwinpthread.a library that no contains version.o (version.rc) to avoid including the resource in the executables due to the "--whole-archive" flag
		OSSEC_CFLAGS+=-Wl,-L,win32/ -Wl,-Bstatic,--whole-archive -lwinpthreadpatched -Wl,--no-whole-archive -Wl,-Bdynamic -ldelayimp -pthread -DBUILDING_LIBCURL="" -DPCRE2_EXP_DECL=""
		OSSEC_LDFLAGS+=-Wl,-L,win32/ -Wl,-Bstatic,--whole-archive -lwinpthreadpatched -Wl,--no-whole-archive -Wl,-Bdynamic -ldelayimp -pthread -DBUILDING_LIBCURL="" -DPCRE2_EXP_DECL=""
		AR_LDFLAGS+=-Wl,-L,win32/ -Wl,-Bstatic,--whole-archive -lwinpthreadpatched -Wl,--no-whole-archive -Wl,-Bdynamic -ldelayimp -pthread -DBUILDING_LIBCURL="" -DPCRE2_EXP_DECL=""
		PRECOMPILED_OS:=windows
endif # winagent

ifeq (${IMAGE_TRUST_CHECKS}, 0)
	DEFINES+=-DIMAGE_TRUST_CHECKS=0
else ifeq (${IMAGE_TRUST_CHECKS}, 1)
	DEFINES+=-DIMAGE_TRUST_CHECKS=1
else ifeq (${IMAGE_TRUST_CHECKS}, 2)
	DEFINES+=-DIMAGE_TRUST_CHECKS=2
endif

ifeq (${TARGET}, winagent)
	DEFINES+=-DCA_NAME='"${CA_NAME}"'
else
	DEFINES+=-DCA_NAME='${CA_NAME}'
endif

ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
	DEFINES+=-DENABLE_SYSC
endif

ifeq (,$(filter ${DISABLE_CISCAT},YES yes y Y 1))
	DEFINES+=-DENABLE_CISCAT
endif

ifneq (,$(filter ${DEBUGAD},YES yes y Y 1))
	DEFINES+=-DDEBUGAD
endif

# Check if symbol table should be included in release
ifeq (${uname_S},Linux)
	ifneq ($(CHECK_CENTOS5),YES)
		SYMBOLS_IN_RELEASE = YES
	endif
else ifeq (${uname_S},Darwin)
	SYMBOLS_IN_RELEASE = YES
else ifeq (${TARGET},winagent)
	SYMBOLS_IN_RELEASE = YES
endif


ifneq (,$(SYMBOLS_IN_RELEASE))
	OSSEC_CFLAGS+=-g
	AR_LDFLAGS+=-g
	CMAKE_OPTS+=-DCMAKE_SYMBOLS_IN_RELEASE=ON
	ifeq (,$(filter ${DEBUG},YES yes y Y 1))
		OSSEC_CFLAGS+=-DNDEBUG
		OFLAGS+=-O2
		AR_LDFLAGS+=-s
	endif
else
	ifneq (,$(filter ${DEBUG},YES yes y Y 1))
		OSSEC_CFLAGS+=-g
		AR_LDFLAGS+=-g
	else
		OSSEC_CFLAGS+=-DNDEBUG
		OFLAGS+=-O2
		AR_LDFLAGS+=-s
	endif
endif

OSSEC_CFLAGS+=${OFLAGS}
OSSEC_LDFLAGS+=${OFLAGS}
AR_LDFLAGS+=${OFLAGS}

DBSYNC_LIB+=-ldbsync
RSYNC_LIB+=-lrsync

ifeq (${TARGET}, winagent)
	OSSEC_LDFLAGS+=-L${DBSYNC}build/bin
	OSSEC_LDFLAGS+=-L${RSYNC}build/bin
else
	OSSEC_LDFLAGS+=-L${DBSYNC}build/lib
	OSSEC_LDFLAGS+=-L${RSYNC}build/lib
endif

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
OSSEC_CFLAGS+=-I./ -I./headers/ -I${EXTERNAL_OPENSSL}include -I$(EXTERNAL_JSON) -I${EXTERNAL_LIBYAML}include -I${EXTERNAL_CURL}include -I${EXTERNAL_MSGPACK}include -I${EXTERNAL_BZIP2} -I${SHARED_MODULES}common -I${DBSYNC}include -I${RSYNC}include -I${SYSCOLLECTOR}include  -I${SYSINFO}include  -I${EXTERNAL_LIBPCRE2}include -I${EXTERNAL_RPM}/builddir/output/include -I${SYSCHECK}include -I${ROUTER}include -I${CONTENT_MANAGER}include -I${VULNERABILITY_SCANNER}include -I${INVENTORY_HARVESTER}include -I./shared_modules/

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
OSSEC_CCBIN   		=${QUIET_CCBIN}${MING_BASE}${CC}
OSSEC_CXXBIN  		=${QUIET_CCBIN}${MING_BASE}${CXX}
OSSEC_SHARED  		=${QUIET_CCBIN}${MING_BASE}${CC} -shared
OSSEC_LINK    		=${QUIET_LINK}${MING_BASE}ar -crus
OSSEC_REMOVE_OBJECT =${QUIET_LINK}${MING_BASE}ar -d
OSSEC_RANLIB  		=${QUIET_RANLIB}${MING_BASE}ranlib
OSSEC_WINDRES 		=${QUIET_CCBIN}${MING_BASE}windres

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

ifeq (${TARGET}, winagent)
	OSSEC_LDFLAGS+=-L${SYSCOLLECTOR}build/bin
	OSSEC_LDFLAGS+=-L${SYSINFO}build/bin
	OSSEC_LDFLAGS+=-L${SYSCHECK}build/lib
	OSSEC_LDFLAGS+=-L${SYSCHECK}build/bin
else
	OSSEC_LDFLAGS+=-L${SYSCOLLECTOR}build/lib
	OSSEC_LDFLAGS+=-L${SYSINFO}build/lib
	OSSEC_LDFLAGS+=-L${SYSCHECK}build/lib
endif

ifeq (,$(filter ${DISABLE_SYSC}, YES yes y Y 1))
	SYSCOLLECTOR_LIB+=-lsyscollector
endif

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

ifeq (${TARGET},agent)
	DEFINES+=-DCLIENT
endif

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
	@echo "   make TARGET=agent DEBUG=yes"

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

BUILD_SERVER+=wazuh-maild -
BUILD_SERVER+=wazuh-csyslogd -
BUILD_SERVER+=wazuh-agentlessd -
BUILD_SERVER+=wazuh-execd -
BUILD_SERVER+=wazuh-logcollector -
BUILD_SERVER+=wazuh-remoted
BUILD_SERVER+=wazuh-agentd
BUILD_SERVER+=manage_agents
BUILD_SERVER+=utils
BUILD_SERVER+=active-responses
BUILD_SERVER+=wazuh-syscheckd
BUILD_SERVER+=wazuh-monitord
BUILD_SERVER+=wazuh-reportd
BUILD_SERVER+=wazuh-authd
BUILD_SERVER+=wazuh-analysisd
BUILD_SERVER+=wazuh-logtest-legacy
BUILD_SERVER+=wazuh-dbd -
BUILD_SERVER+=wazuh-integratord
BUILD_SERVER+=wazuh-modulesd
BUILD_SERVER+=wazuh-db
BUILD_SERVER+=wazuh-keystore

BUILD_AGENT+=wazuh-agentd
BUILD_AGENT+=agent-auth
BUILD_AGENT+=wazuh-logcollector
BUILD_AGENT+=wazuh-syscheckd
BUILD_AGENT+=wazuh-execd
BUILD_AGENT+=manage_agents
BUILD_AGENT+=active-responses
BUILD_AGENT+=wazuh-modulesd

BUILD_CMAKE_PROJECTS+=build_sysinfo
BUILD_CMAKE_PROJECTS+=build_shared_modules
ifeq (${TARGET},server)
BUILD_CMAKE_PROJECTS+=build_wazuh_cmake
endif
ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
ifneq (${uname_S},HP-UX)
BUILD_CMAKE_PROJECTS+=build_syscollector
endif
endif

${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}: ${libstdc++_path}
	cp $< $@
ifneq (${uname_S},AIX)
	${STRIP_TOOL} -x $@
endif

${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME}: ${libgcc_s_path}
	cp $< $@
ifneq (${uname_S},AIX)
	${STRIP_TOOL} -x $@
endif

.PHONY: server local hybrid agent selinux

ifeq (${MAKECMDGOALS},server)
$(error Do not use 'server' directly, use 'TARGET=server')
endif
server: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},local)
$(error Do not use 'local' directly, use 'TARGET=local')
endif
local: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},hybrid)
$(error Do not use 'hybrid' directly, use 'TARGET=hybrid')
endif
hybrid: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},agent)
$(error Do not use 'agent' directly, use 'TARGET=agent')
endif

agent: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_CMAKE_PROJECTS}
	${MAKE} ${BUILD_AGENT}

ifneq (,$(filter ${USE_SELINUX},YES yes y Y 1))
server local hybrid agent: selinux
endif

selinux: $(SELINUX_POLICY)

$(SELINUX_POLICY): $(SELINUX_MODULE)
	semodule_package -o $@ -m $?

$(SELINUX_MODULE): $(SELINUX_ENFORCEMENT)
	checkmodule -M -m -o $@ $?

WINDOWS_LIBS:=win32/syscollector win32/syscheck
WINDOWS_BINS:=win32/wazuh-agent.exe win32/wazuh-agent-eventchannel.exe win32/manage_agents.exe win32/setup-windows.exe win32/setup-syscheck.exe win32/setup-iis.exe win32/os_win32ui.exe win32/agent-auth.exe
WINDOWS_ACTIVE_RESPONSES:=win32/restart-wazuh.exe win32/route-null.exe win32/netsh.exe

ifeq (${MAKECMDGOALS},winagent)
$(error Do not use 'winagent' directly, use 'TARGET=winagent')
endif
.PHONY: winagent
winagent: external win32/libwinpthread-1.dll win32/libwinpthreadpatched.a ${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME} ${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME} win32/version-dll.o win32/version-app.o
	${MAKE} ${WAZUHEXT_LIB} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1" LIBS="-lwsock32 -lws2_32 -lcrypt32"
	${MAKE} ${WINDOWS_LIBS} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1"
	${MAKE} ${WINDOWS_BINS} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1" LIBS="-lwsock32 -lwevtapi -lshlwapi -lcomctl32 -ladvapi32 -lkernel32 -lpsapi -lgdi32 -liphlpapi -lws2_32 -lcrypt32 -lwintrust -lmpr"
	${MAKE} ${WINDOWS_ACTIVE_RESPONSES} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1" LIBS="-lwsock32 -lwevtapi -lshlwapi -lcomctl32 -ladvapi32 -lkernel32 -lpsapi -lgdi32 -liphlpapi -lws2_32 -lcrypt32 -lwintrust -lmpr"
	cd win32/ && ./unix2dos.pl ossec.conf > default-ossec.conf
	cd win32/ && ./unix2dos.pl help.txt > help_win.txt
	cd win32/ && ./unix2dos.pl ../../etc/internal_options.conf > internal_options.conf
	cd win32/ && ./unix2dos.pl ../../etc/local_internal_options-win.conf > default-local_internal_options.conf
	cd win32/ && ./unix2dos.pl ../../LICENSE > LICENSE.txt
	cd win32/ && ./unix2dos.pl ../../VERSION.json > VERSION.json
	cd win32/ && makensis wazuh-installer.nsi

win32/shared_modules: $(WAZUHEXT_LIB)
	cd ${DBSYNC} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${DBSYNC_TEST} ${SHARED_MODULES_RELEASE_TYPE} ${WIN_RESOURCE_OBJ} .. && ${MAKE}
	cd ${RSYNC} &&  mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${RSYNC_TEST} ${SHARED_MODULES_RELEASE_TYPE} ${WIN_RESOURCE_OBJ} .. && ${MAKE}

#### Sysinfo ##

win32/sysinfo: $(WAZUHEXT_LIB) win32/version-dll.o
	cd ${SYSINFO} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${SYSINFO_OS} ${SYSINFO_TEST} ${SYSINFO_RELEASE_TYPE} ${WIN_RESOURCE_OBJ} .. && ${MAKE}

#### Syscollector ##
win32/syscollector: win32/shared_modules win32/sysinfo win32/version-dll.o
	cd ${SYSCOLLECTOR} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${SYSCOLLECTOR_TEST} ${SYSCOLLECTOR_RELEASE_TYPE} ${WIN_RESOURCE_OBJ} .. && ${MAKE}

win32/syscheck: win32/shared_modules $(WAZUHEXT_LIB)
	cd ${SYSCHECK} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${SYSCHECK_TEST} ${SYSCHECK_RELEASE_TYPE} ${WIN_RESOURCE_OBJ} .. && ${MAKE}

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
FLATBUFFERS_LIB = $(EXTERNAL_FLATBUFFERS)build/libflatbuffers.a
LZMA_LIB = $(EXTERNAL_LZMA)build/liblzma.a
LUA_LIB = ${EXTERNAL_LUA}install/lib/liblua.a
LIBBPF_LIB = $(EXTERNAL_LIBBPF)build/modern.bpf.o

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
	EXTERNAL_LIBS_NO_WHOLE += $(ROCKSDB_LIB) $(FLATBUFFERS_LIB)
	EXTERNAL_LIBS += $(LZMA_LIB) $(MINIZIP_LIB)
endif

ifneq (${TARGET},winagent)
EXTERNAL_LIBS += $(MSGPACK_LIB)
ifneq (${TARGET},agent)
EXTERNAL_LIBS += $(LIBFFI_LIB) $(BZIP2_LIB)
endif
ifeq (${uname_S},Linux)
ifneq ($(CHECK_CENTOS5),YES)
EXTERNAL_LIBS +=  ${LUA_LIB} ${RPM_LIB} ${POPT_LIB}
endif
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
EXTERNAL_LIBS += ${AUDIT_LIB}
endif

ifeq ($(CHECK_CENTOS5),YES)
EXTERNAL_LIBS += $(PROCPS_LIB)
else
EXTERNAL_LIBS += $(PROCPS_LIB) $(LIBALPM_LIB) $(LIBARCHIVE_LIB)
endif
endif
endif
ifeq (${uname_S},Darwin)
EXTERNAL_LIBS += ${LIBPLIST_LIB}
endif


.PHONY: external test_external
external: test_external $(EXTERNAL_LIBS) $(JEMALLOC_LIB)

ifneq (,$(filter ${TEST},YES yes y Y 1))
external: build_gtest build_benchmark
endif

ifeq (${TARGET},server)
external: $(ROCKSDB_LIB)
endif

ifeq (${uname_S},Linux)
ifneq ($(CHECK_CENTOS5),YES)
ifneq (${TARGET},winagent)
external: ${LIBBPF_LIB}
endif
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
ifeq (${uname_S},HP-UX)
	cd ${EXTERNAL_OPENSSL} && MAKE=gmake ./Configure $(OPENSSL_FLAGS) hpux-ia64-gcc && ${MAKE} build_libs
else
ifeq (${uname_S},AIX)
	cd ${EXTERNAL_OPENSSL} && ./config aix-gcc $(OPENSSL_FLAGS) && ${MAKE} build_libs
else
ifeq (${uname_S},SunOS)
ifeq ($(uname_M),i86pc)
	cd ${EXTERNAL_OPENSSL} && ./Configure $(OPENSSL_FLAGS) solaris-x86-gcc && ${MAKE} build_libs
else
	cd ${EXTERNAL_OPENSSL} && ./Configure $(OPENSSL_FLAGS) solaris-sparcv9-gcc && ${MAKE} build_libs
endif
else
	cd ${EXTERNAL_OPENSSL} && ./config $(OPENSSL_FLAGS) && ${MAKE} build_libs
endif
endif
endif
endif
endif

#### libbpf-bootstrap #########

$(LIBBPF_LIB):
	cd $(EXTERNAL_LIBBPF) && mkdir -p build && cd build && cmake .. && ${MAKE}

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
ifneq (,$(filter ${uname_M},aarch64 ppc64le))
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
	 ${MAKE} -C $(EXTERNAL_LIBARCHIVE)

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
ifeq (${uname_S},SunOS)
ifeq (${uname_R},5.10)
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC ./configure --enable-jit=no --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}
else
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC ./configure --enable-jit=auto --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}
endif
else
ifeq (${CHECK_CENTOS5},YES)
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC ./configure --enable-jit=no --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}
else
	cd $(EXTERNAL_LIBPCRE2) && CFLAGS=-fPIC ./configure --enable-jit=auto --disable-shared && mkdir -p include && cp src/pcre2.h include/pcre2.h && ${MAKE}
endif
endif
endif

### popt lib ###

POPT_BUILD_DIR = $(EXTERNAL_POPT)build/

$(POPT_LIB): $(POPT_BUILD_DIR)Makefile
	 $(MAKE) -C $(POPT_BUILD_DIR)
$(POPT_BUILD_DIR)Makefile:
	mkdir -p $(POPT_BUILD_DIR) && cd $(POPT_BUILD_DIR) && cmake ..

### lua lib ###

$(LUA_LIB):
ifeq (${TARGET},winagent)
	cd ${EXTERNAL_LUA} && make mingw CC=${MING_BASE}${CC} MYCFLAGS='-fPIC' && make local TO_BIN='lua.exe luac.exe'
else
ifeq (${uname_S},Darwin)
	cd ${EXTERNAL_LUA} && make macosx MYCFLAGS='-fPIC' && make local
else
ifeq (${uname_S},SunOS)
	cd ${EXTERNAL_LUA} && gmake solaris MYCFLAGS='-fPIC' && gmake local INSTALL='cp -p' INSTALL_EXEC='cp -p' INSTALL_DATA='cp -p'
else
ifeq ($(findstring BSD,${uname_S}), BSD)
	cd ${EXTERNAL_LUA} && make bsd MYCFLAGS='-fPIC' && make local
else
ifeq (${uname_S},AIX)
	cd ${EXTERNAL_LUA} && make aix MYCFLAGS='-fPIC' && make local
else
	cd ${EXTERNAL_LUA} && make posix MYCFLAGS='-fPIC' && make local
endif
endif
endif
endif
endif

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
DEPS_VERSION = 46-30554
RESOURCES_URL_BASE := https://packages.wazuh.com/deps/
RESOURCES_URL := $(RESOURCES_URL_BASE)$(DEPS_VERSION)
CPYTHON := cpython
PYTHON_SOURCE := no

ifneq (${TARGET}, winagent)
ifneq (,$(filter ${uname_S},Linux Darwin HP-UX))
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
else
ifneq (,$(filter ${uname_S},SunOS AIX))
	cpu_arch := ${uname_P}
ifeq (${cpu_arch},powerpc)
	PRECOMPILED_ARCH := /powerpc
else
ifneq (,$(filter ${cpu_arch},sparc sun4u))
	PRECOMPILED_ARCH := /sparc
else
ifneq (,$(filter ${cpu_arch},i386 i86pc))
	PRECOMPILED_ARCH := /i386
else
	PRECOMPILED_ARCH := /${uname_M}
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
endif

# Define CPYTHON pre-compile
CPYTHON_ARCHIVE := cpython_x86_64
ifeq ($(PRECOMPILED_ARCH),/aarch64)
	CPYTHON_ARCHIVE := cpython_arm64
else
	CPYTHON_ARCHIVE := cpython_x86_64
endif

ifeq ($(CHECK_CENTOS5),YES)
PRECOMPILED_OS := el5
# Avoid the linkage of incompatible libraries in Data Provider for CentOS 5 and Red Hat 5
SYSINFO_OS+=-DCMAKE_CHECK_CENTOS5=1
SYSCHECK_OS=-DCMAKE_CHECK_CENTOS5=1
endif

ifeq (,$(filter ${EXTERNAL_SRC_ONLY},YES yes y Y 1))
# If EXTERNAL_SRC_ONLY=YES is not defined, lets look for the precompiled lib
PRECOMPILED_RES := $(PRECOMPILED_OS)$(PRECOMPILED_ARCH)
endif

# Agent dependencies
EXTERNAL_RES := cJSON curl libdb libffi libyaml openssl procps sqlite zlib audit-userspace msgpack bzip2 nlohmann googletest libpcre2 libplist pacman libarchive popt lua rpm rocksdb lzma cpp-httplib benchmark libbpf-bootstrap
ifneq (${TARGET},agent)
ifneq (${TARGET},winagent)
	# Manager extra dependency
	EXTERNAL_RES += $(CPYTHON) jemalloc flatbuffers
endif
endif

# Check the target and remove libbpf-bootstrap if the target is winagent OR non-Linux OS
ifeq (${TARGET}, winagent)
	EXTERNAL_RES := $(filter-out libbpf-bootstrap, $(EXTERNAL_RES))
else
ifneq (${uname_S}, Linux)
	EXTERNAL_RES := $(filter-out libbpf-bootstrap, $(EXTERNAL_RES))
endif
endif

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
	-cd external && [ -f $(patsubst external-precompiled/%,%,$@) ] && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	-cd external && [ -f $(patsubst external-precompiled/%.gz,%,$@) ] && $(TAR) $(patsubst external-precompiled/%.gz,%,$@) || true
	-[ -f external/$(patsubst external-precompiled/%.gz,%,$@) ] && rm external/$(patsubst external-precompiled/%.gz,%,$@) || true
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
	-cd external && [ -f $(patsubst external-precompiled/%,%,$@) ] && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	-cd external && [ -f $(patsubst external-precompiled/%.gz,%,$@) ] && $(TAR) $(patsubst external-precompiled/%.gz,%,$@) || true
	-[ -f external/$(patsubst external-precompiled/%.gz,%,$@) ] && rm external/$(patsubst external-precompiled/%.gz,%,$@) || true
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
ifeq (${TARGET}, winagent)
# libwazuhext
WAZUHEXT_DLL = libwazuhext.$(SHARED)
WAZUHEXT_LIB = libwazuhext.lib
WAZUHEXT_LIB_DEF = libwazuhext.def
# libwazuhshared
WAZUH_DLL = libwazuhshared.$(SHARED)
WAZUH_LIB = libwazuhshared.lib
WAZUH_DEF = libwazuhshared.def
else
WAZUHEXT_LIB = libwazuhext.$(SHARED)
WAZUH_LIB = libwazuhshared.$(SHARED)
endif
BUILD_LIBS = libwazuh.a $(WAZUHEXT_LIB)

$(BUILD_SERVER) $(BUILD_AGENT) $(WINDOWS_BINS) $(WINDOWS_BINS): $(BUILD_LIBS)

#### os_xml ########

os_xml_c := $(wildcard os_xml/*.c)
os_xml_o := $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

#### os_regex ######

os_regex_c := $(wildcard os_regex/*.c)
os_regex_o := $(os_regex_c:.c=.o)

os_regex/%.o: os_regex/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

#### os_net ##########

os_net_c := $(wildcard os_net/*.c)
os_net_o := $(os_net_c:.c=.o)

os_net/%.o: os_net/%.c
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

wrappers_macos_c := $(wildcard unit_tests/wrappers/macos/*.c)
wrappers_macos_o := $(wrappers_macos_c:.c=.o)

wrappers_macos_libc_c := $(wildcard unit_tests/wrappers/macos/libc/*.c)
wrappers_macos_libc_o := $(wrappers_macos_libc_c:.c=.o)

wrappers_macos_posix_c := $(wildcard unit_tests/wrappers/macos/posix/*.c)
wrappers_macos_posix_o := $(wrappers_macos_posix_c:.c=.o)

wrappers_posix_c := $(wildcard unit_tests/wrappers/posix/*.c)
wrappers_posix_o := $(wrappers_posix_c:.c=.o)

wrappers_wazuh_c := $(wildcard unit_tests/wrappers/wazuh/*.c)
wrappers_wazuh_o := $(wrappers_wazuh_c:.c=.o)

wrappers_wazuh_os_crypto_c := $(wildcard unit_tests/wrappers/wazuh/os_crypto/*.c)
wrappers_wazuh_os_crypto_o := $(wrappers_wazuh_os_crypto_c:.c=.o)

wrappers_wazuh_os_execd_c := $(wildcard unit_tests/wrappers/wazuh/os_execd/*.c)
wrappers_wazuh_os_execd_o := $(wrappers_wazuh_os_execd_c:.c=.o)

wrappers_wazuh_os_net_c := $(wildcard unit_tests/wrappers/wazuh/os_net/*.c)
wrappers_wazuh_os_net_o := $(wrappers_wazuh_os_net_c:.c=.o)

wrappers_wazuh_os_regex_c := $(wildcard unit_tests/wrappers/wazuh/os_regex/*.c)
wrappers_wazuh_os_regex_o := $(wrappers_wazuh_os_regex_c:.c=.o)

wrappers_wazuh_os_xml_c := $(wildcard unit_tests/wrappers/wazuh/os_xml/*.c)
wrappers_wazuh_os_xml_o := $(wrappers_wazuh_os_xml_c:.c=.o)

wrappers_wazuh_shared_c := $(wildcard unit_tests/wrappers/wazuh/shared/*.c)
wrappers_wazuh_shared_o := $(wrappers_wazuh_shared_c:.c=.o)

wrappers_wazuh_syscheckd_c := $(wildcard unit_tests/wrappers/wazuh/syscheckd/*.c)
wrappers_wazuh_syscheckd_o := $(wrappers_wazuh_syscheckd_c:.c=.o)

wrappers_wazuh_wazuh_db_c := $(wildcard unit_tests/wrappers/wazuh/wazuh_db/*.c)
wrappers_wazuh_wazuh_db_o := $(wrappers_wazuh_wazuh_db_c:.c=.o)

wrappers_wazuh_wazuh_modules_c := $(wildcard unit_tests/wrappers/wazuh/wazuh_modules/*.c)
wrappers_wazuh_wazuh_modules_o := $(wrappers_wazuh_wazuh_modules_c:.c=.o)

wrappers_wazuh_monitord_c := $(wildcard unit_tests/wrappers/wazuh/monitord/*.c)
wrappers_wazuh_monitord_o := $(wrappers_wazuh_monitord_c:.c=.o)

wrappers_wazuh_os_auth_c := $(wildcard unit_tests/wrappers/wazuh/os_auth/*.c)
wrappers_wazuh_os_auth_o := $(wrappers_wazuh_os_auth_c:.c=.o)

wrappers_wazuh_addagent_c := $(wildcard unit_tests/wrappers/wazuh/addagent/*.c)
wrappers_wazuh_addagent_o := $(wrappers_wazuh_addagent_c:.c=.o)

wrappers_client_agent_c := $(wildcard unit_tests/wrappers/wazuh/client-agent/*.c)
wrappers_client_agent_o := $(wrappers_client_agent_c:.c=.o)

wrappers_wazuh_config_c := $(wildcard unit_tests/wrappers/wazuh/config/*.c)
wrappers_wazuh_config_o := $(wrappers_wazuh_config_c:.c=.o)

wrappers_data_provider_c := $(wildcard unit_tests/wrappers/wazuh/data_provider/*.c)
wrappers_data_provider_o := $(wrappers_data_provider_c:.c=.o)

wrappers_logcollector_c := $(wildcard unit_tests/wrappers/wazuh/logcollector/*.c)
wrappers_logcollector_o := $(wrappers_logcollector_c:.c=.o)

wrappers_windows_c := $(wildcard unit_tests/wrappers/windows/*.c)
wrappers_windows_o := $(wrappers_windows_c:.c=.o)

wrappers_windows_lib_c := $(wildcard unit_tests/wrappers/windows/libc/*.c)
wrappers_windows_lib_o := $(wrappers_windows_lib_c:.c=.o)

wrappers_windows_posix_c := $(wildcard unit_tests/wrappers/windows/posix/*.c)
wrappers_windows_posix_o := $(wrappers_windows_posix_c:.c=.o)

wrappers_wazuh_remoted_c := $(wildcard unit_tests/wrappers/wazuh/remoted/*.c)
wrappers_wazuh_remoted_o := $(wrappers_wazuh_remoted_c:.c=.o)

wrappers_wazuh_analysisd_c := $(wildcard unit_tests/wrappers/wazuh/analysisd/*.c)
wrappers_wazuh_analysisd_o := $(wrappers_wazuh_analysisd_c:.c=.o)

wrappers_wazuh_shared_modules_c := $(wildcard unit_tests/wrappers/wazuh/shared_modules/*.c)
wrappers_wazuh_shared_modules_o := $(wrappers_wazuh_shared_modules_c:.c=.o)

ifneq (,$(filter ${TEST},YES yes y Y 1))
	OSSEC_CFLAGS+=${CFLAGS_TEST}
	OSSEC_LDFLAGS+=${CFLAGS_TEST}
	AR_LDFLAGS+=${CFLAGS_TEST}
	OSSEC_LIBS+=${LIBS_TEST}

	UNIT_TEST_WRAPPERS:=${wrappers_common_o}
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
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_execd_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_net_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_regex_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_xml_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_shared_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_syscheckd_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_wazuh_db_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_wazuh_modules_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_monitord_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_os_auth_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_addagent_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_config_o}
	UNIT_TEST_WRAPPERS+=${wrappers_client_agent_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_remoted_o}
	UNIT_TEST_WRAPPERS+=${wrappers_wazuh_analysisd_o}
	UNIT_TEST_WRAPPERS+=${wrappers_data_provider_o}
	UNIT_TEST_WRAPPERS+=${wrappers_logcollector_o}

	ifeq (${TARGET},winagent)
		UNIT_TEST_WRAPPERS+=${wrappers_windows_o}
		UNIT_TEST_WRAPPERS+=${wrappers_windows_lib_o}
		UNIT_TEST_WRAPPERS+=${wrappers_windows_posix_o}
	else ifeq (${uname_S},Darwin)
	    UNIT_TEST_WRAPPERS+=${wrappers_macos_o}
		UNIT_TEST_WRAPPERS+=${wrappers_macos_libc_o}
		UNIT_TEST_WRAPPERS+=${wrappers_macos_posix_o}
	else
		UNIT_TEST_WRAPPERS+=${wrappers_externals_audit_o}
		UNIT_TEST_WRAPPERS+=${wrappers_externals_procpc_o}
		UNIT_TEST_WRAPPERS+=${wrappers_linux_o}
	endif

	ifeq (${TARGET},server)
		UNIT_TEST_WRAPPERS+=${wrappers_wazuh_shared_modules_o}
	endif
endif #TEST

shared_c := $(wildcard shared/*.c)
shared_o := $(shared_c:.c=.o)

shared/%.o: shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -DARGV0=\"wazuh-remoted\" -c $^ -o $@

shared/debug_op_proc.o: shared/debug_op.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -DMA -DARGV0=\"wazuh-remoted\" -c $^ -o $@

shared/file_op_proc.o: shared/file_op.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -DCLIENT -DARGV0=\"wazuh-remoted\" -c $^ -o $@

#### Wazuh DB ####

wdb_sql := $(wildcard wazuh_db/*.sql)
wdblib_c := $(wildcard wazuh_db/wdb*.c)
wdbhelpers_c := $(wildcard wazuh_db/helpers/*.c)
wdbshared_c := wazuh_db/wdb_shared.c
wdblib_o := $(wdblib_c:.c=.o) $(wdb_sql:.sql=.o)
wdb_o := wazuh_db/main.o $(wdblib_o:.c=.o) $(wdb_c:.c=.o) $(wdb_sql:.sql=.o) $(wdbshared_c:.c=.o)

wazuh_db/schema_%.o: wazuh_db/schema_%.sql
	${QUIET_CC}echo 'const char *'$(word 2, $(subst /, ,$(subst .,_,$<))) '= "'"`cat $< | tr -d \"\n\"`"'";' | ${MING_BASE}${CC} ${OSSEC_CFLAGS} -xc -c -o $@ -

wazuh_db/%.o: wazuh_db/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-db\" -c $^ -o $@

wazuh-db: ${wdb_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} ${WAZUH_LDFLAGS} $^ ${OSSEC_LIBS} ${WAZUH_LIBS} -o $@

#### Config ##########

config_c := $(wildcard config/*.c)
config_o := $(config_c:.c=.o)

config/%.o: config/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

build_shared_modules: $(WAZUHEXT_LIB)
	cd ${DBSYNC} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${DBSYNC_TEST} ${SHARED_MODULES_RELEASE_TYPE} .. && ${MAKE}
	cd ${RSYNC} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${RSYNC_TEST} ${SOLARIS_CMAKE_OPTS} ${SHARED_MODULES_RELEASE_TYPE} .. && ${MAKE}

#### Sysinfo ##
build_sysinfo: $(WAZUHEXT_LIB)
	cd ${SYSINFO} && mkdir -p build && cd build && cmake ${CMAKE_OPTS} ${SYSINFO_OS} ${SYSINFO_TEST} ${SYSINFO_RELEASE_TYPE} .. && ${MAKE}

#### Syscollector ##
ifeq (,$(filter ${DISABLE_SYSC}, YES yes y Y 1))
build_syscollector: build_shared_modules build_sysinfo
	cd ${SYSCOLLECTOR} && mkdir -p build && cd build && cmake -DTARGET=${TARGET} ${CMAKE_OPTS} ${SOLARIS_CMAKE_OPTS} ${SYSCOLLECTOR_TEST} ${SYSCOLLECTOR_RELEASE_TYPE} .. && ${MAKE}
endif

#### Wazuh cmake ###
build_wazuh_cmake: $(WAZUHEXT_LIB) $(EXTERNAL_LIBS_NO_WHOLE) build_syscollector
	mkdir -p build && cd build && cmake .. -DTARGET=${TARGET} ${CMAKE_OPTS} ${WAZUH_RELEASE_TYPE} ${WAZUH_TEST} && ${MAKE}

#### Wazuh modules ##
wmodules_c := $(wildcard wazuh_modules/wm*.c) $(wildcard wazuh_modules/agent_upgrade/*.c)

ifeq (${TARGET},agent)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/agent_upgrade/agent/*.c)
else ifeq (${TARGET},winagent)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/agent_upgrade/agent/*.c)
else
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/task_manager/*.c)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/agent_upgrade/manager/*.c)
endif

wmodules_o := $(wmodules_c:.c=.o)

wazuh_modules/%.o: wazuh_modules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

wmodules_dep := ${wmodules_o} ${wdbhelpers_c:.c=.o} wazuh_db/wdb_shared.o

ifeq (${uname_S},HP-UX)
	wmodules_dep := ${wmodules_dep} ${config_o}
endif

#### crypto ##########

crypto_blowfish_c := os_crypto/blowfish/bf_op.c
crypto_blowfish_o := $(crypto_blowfish_c:.c=.o)

os_crypto/blowfish/%.o: os_crypto/blowfish/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_md5_c := os_crypto/md5/md5_op.c
crypto_md5_o := $(crypto_md5_c:.c=.o)

os_crypto/md5/%.o: os_crypto/md5/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_sha1_c := os_crypto/sha1/sha1_op.c
crypto_sha1_o := $(crypto_sha1_c:.c=.o)

os_crypto/sha1/%.o: os_crypto/sha1/%.c
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

crypto_md5_sha1_c := os_crypto/md5_sha1/md5_sha1_op.c
crypto_md5_sha1_o := $(crypto_md5_sha1_c:.c=.o)

os_crypto/md5_sha1/%.o: os_crypto/md5_sha1/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_md5_sha1_sha256_c := os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.c
crypto_md5_sha1_sha256_o := $(crypto_md5_sha1_sha256_c:.c=.o)

os_crypto/md5_sha1_sha256/%.o: os_crypto/md5_sha1_sha256/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_hmac_c := os_crypto/hmac/hmac.c
crypto_hmac_o := $(crypto_hmac_c:.c=.o)

os_crypto/hmac/%.o: os_crypto/hmac/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_shared_c := $(wildcard os_crypto/shared/*.c)
crypto_shared_o := $(crypto_shared_c:.c=.o)

os_crypto/shared/%.o: os_crypto/shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@

crypto_signature_c := $(wildcard os_crypto/signature/*.c)
crypto_signature_o := $(crypto_signature_c:.c=.o)

os_crypto/signature/%.o: os_crypto/signature/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@

analysisd/logmsg.o: analysisd/logmsg.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@


crypto_o := ${crypto_blowfish_o} \
					 ${crypto_md5_o} \
					 ${crypto_sha1_o} \
					 ${crypto_shared_o} \
					 ${crypto_md5_sha1_o} \
					 ${crypto_md5_sha1_sha256_o} \
					 ${crypto_sha256_o} \
					 ${crypto_sha512_o} \
					 ${crypto_aes_o} \
					 ${crypto_hmac_o} \
					 ${crypto_signature_o}

#### libwazuh #########

libwazuh.a: ${config_o} ${wmodules_dep} ${crypto_o} ${shared_o} ${os_net_o} ${os_regex_o} ${os_xml_o} ${os_zlib_o} ${UNIT_TEST_WRAPPERS} os_auth/ssl.o os_auth/check_cert.o addagent/validate.o ${manage_agents} analysisd/logmsg.o
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

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
ifeq (${uname_S},SunOS)
ifneq ($(uname_R),5.10)
LIBGCC_FLAGS := -static-libgcc
else
LIBGCC_FLAGS := -Wl,-rpath,\$$ORIGIN
endif
ifeq (${uname_P},sparc)
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -mimpure-text -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
else
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
else
ifeq (${uname_S},AIX)
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	mkdir -p libwazuhext;
	find external/ -name \*.a -exec cp {} libwazuhext/ \;
	for lib in libcjson.a libz.a libmsgpack.a libssl.a libcrypto.a libsqlite3.a libyaml.a libpcre2-8.a ; do \
		ar -x libwazuhext/$$lib; \
		mv *.o libwazuhext/; \
	done
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) libwazuhext/*.o -o $@ -static-libgcc -latomic -lm
else
ifeq (${uname_S},HP-UX)
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	mkdir -p libwazuhext;
	find external/ -name \*.a -exec cp {} libwazuhext/ \;
	for lib in libcjson.a libz.a libmsgpack.a libssl.a libcrypto.a libsqlite3.a libyaml.a libpcre2-8.a ; do \
		ar -x libwazuhext/$$lib; \
		mv *.o libwazuhext/; \
	done
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) libwazuhext/*.o -o $@ -static-libgcc
else
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
endif
endif
endif
endif

#### os_mail #########

os_maild_c := $(wildcard os_maild/*.c)
os_maild_o := $(os_maild_c:.c=.o)

os_maild/%.o: os_maild/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-maild\" -c $^ -o $@

wazuh-maild: ${os_maild_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### os_dbd ##########

os_dbd_c := $(wildcard os_dbd/*.c)
os_dbd_o := $(os_dbd_c:.c=.o)

os_dbd/%.o: os_dbd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${MI} ${PI} -DARGV0=\"wazuh-dbd\" -c $^ -o $@

wazuh-dbd: ${os_dbd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} ${MI} ${PI} $^  ${OSSEC_LIBS} -o $@


#### os_csyslogd #####

os_csyslogd_c := $(wildcard os_csyslogd/*.c)
os_csyslogd_o := $(os_csyslogd_c:.c=.o)

os_csyslogd/%.o: os_csyslogd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-csyslogd\" -c $^ -o $@

wazuh-csyslogd: ${os_csyslogd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### agentlessd ####

os_agentlessd_c := $(wildcard agentlessd/*.c)
os_agentlessd_o := $(os_agentlessd_c:.c=.o)

agentlessd/%.o: agentlessd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-agentlessd\" -c $^ -o $@

wazuh-agentlessd: ${os_agentlessd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### os_execd #####

os_execd_c := $(wildcard os_execd/*.c)
os_execd_o := $(os_execd_c:.c=.o)

os_execd/%.o: os_execd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-execd\" -c $^ -o $@

wazuh-execd: ${os_execd_o} active-response/active_responses.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### logcollectord ####

os_logcollector_c := $(wildcard logcollector/*.c)
os_logcollector_o := $(os_logcollector_c:.c=.o)
os_logcollector_eventchannel_o := $(os_logcollector_c:.c=-event.o)

logcollector/%.o: logcollector/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-logcollector\" -c $^ -o $@

logcollector/%-event.o: logcollector/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DEVENTCHANNEL_SUPPORT -DARGV0=\"wazuh-logcollector\" -c $^ -o $@

wazuh-logcollector: ${os_logcollector_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### remoted #########

remoted_c := $(wildcard remoted/*.c)
remoted_o := $(remoted_c:.c=.o)

remoted/%.o: remoted/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS}  -DPORTABLE_UNALIGNED_ACCESS=0 -I./remoted -DARGV0=\"wazuh-remoted\" -c $^ -o $@

wazuh-remoted: ${remoted_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} ${WAZUH_LDFLAGS} $^ ${OSSEC_LIBS} ${WAZUH_LIBS} -o $@

#### wazuh-agentd ####

client_agent_c := $(wildcard client-agent/*.c)
client_agent_o := $(client_agent_c:.c=.o)

client-agent/%.o: client-agent/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./client-agent -DARGV0=\"wazuh-agentd\" -c $^ -o $@

wazuh-agentd: ${client_agent_o} monitord/rotate_log.o monitord/compress_log.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### addagent ######

addagent_c := $(wildcard addagent/*.c)
addagent_o := $(addagent_c:.c=.o)

addagent/%.o: addagent/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./addagent -DARGV0=\"manage_agents\" -c $^ -o $@


manage_agents: ${addagent_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### Active Response ####

active_response_programs = default-firewall-drop pf npf ipfw firewalld-drop disable-account host-deny ip-customblock restart-wazuh route-null kaspersky wazuh-slack

$(active_response_programs): ${WAZUH_LIB} ${WAZUHEXT_LIB}

# Minimal dependencies for building active responses programs
AR_PROGRAMS_DEPS = os_regex/os_regex.o os_regex/os_regex_compile.o os_regex/os_match_free_pattern.o os_regex/os_regex_maps.o os_regex/os_regex_execute.o os_regex/os_regex_free_pattern.o os_regex/os_match_execute.o os_regex/os_match_compile.o shared/expression.o shared/randombytes.o shared/validate_op.o shared/regex_op.o shared/string_op.o shared/exec_op.o shared/file_op_proc.o shared/debug_op_proc.o shared/time_op.o shared/privsep_op.o shared/version_op.o shared/binaries_op.o os_xml/os_xml.o os_xml/os_xml_access.o os_regex/os_regex_strbreak.o os_net/os_net.o

ifneq (,$(filter ${TEST},YES yes y Y 1))
AR_PROGRAMS_DEPS += unit_tests/wrappers/externals/pcre2/pcre2_wrappers.o
endif

ifeq (${TARGET}, winagent)
ifneq (,$(filter ${TEST},YES yes y Y 1))
AR_PROGRAMS_DEPS += unit_tests/wrappers/common.o unit_tests/wrappers/windows/handleapi_wrappers.o unit_tests/wrappers/windows/fileapi_wrappers.o unit_tests/wrappers/windows/winnetwk_wrappers.o unit_tests/wrappers/windows/stat64_wrappers.o unit_tests/wrappers/windows/processthreadsapi_wrappers.o unit_tests/wrappers/windows/libc/stdio_wrappers.o unit_tests/wrappers/windows/system_calls_wrappers.o
endif
endif

.PHONY: active-responses
active-responses: ${active_response_programs}

active_response_c := $(wildcard active-response/*.c)
active_response_c += $(wildcard active-response/firewalls/*.c)
active_response_o := $(active_response_c:.c=.o)

active-response/%.o: active-response/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./active-response -DARGV0=\"active-responses\" -c $^ -o $@

default-firewall-drop: active-response/firewalls/default-firewall-drop.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

pf: active-response/firewalls/pf.o  active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

npf: active-response/firewalls/npf.o  active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

ipfw: active-response/firewalls/ipfw.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

firewalld-drop: active-response/firewalld-drop.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

disable-account: active-response/disable-account.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

host-deny: active-response/host-deny.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

ip-customblock: active-response/ip-customblock.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

restart-wazuh: active-response/restart-wazuh.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

route-null: active-response/route-null.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

kaspersky: active-response/kaspersky.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

wazuh-slack: active-response/wazuh-slack.o active-response/active_responses.o
	${OSSEC_CCBIN} ${AR_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


### libwazuhshared.so #########

ifeq (${uname_S},Darwin)
WAZUH_SHARED_SHFLAGS=-install_name @rpath/libwazuhshared.$(SHARED)

$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $(WAZUH_SHARED_SHFLAGS) -o $@ -Wl,-all_load $^ $(OSSEC_LIBS)
else
ifeq (${TARGET}, winagent)
$(WAZUH_DLL) $(WAZUH_DEF) : $(WAZUHEXT_DLL) $(AR_PROGRAMS_DEPS) win32/version-dll.o
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -UOSSECHIDS -o $(WAZUH_DLL) -static-libgcc -Wl,--export-all-symbols -Wl,--add-stdcall-alias -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--output-def,$(WAZUH_DEF) ${OSSEC_LIBS}

$(WAZUH_LIB): $(WAZUH_DLL) $(WAZUH_DEF)
	$(DLLTOOL)  -D $(WAZUH_DLL) --def $(WAZUH_DEF) --output-delaylib $@


else
ifeq (${uname_S},SunOS)
ifneq ($(uname_R),5.10)
LIBGCC_FLAGS := -static-libgcc
else
LIBGCC_FLAGS := -Wl,-rpath,\$$ORIGIN
endif
ifeq (${uname_P},sparc)
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -mimpure-text -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
else
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
else
ifneq (,$(filter ${uname_S},AIX HP-UX))
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $^ ${OSSEC_LIBS} -o $@ -static-libgcc
else
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
endif
endif
endif


#### Util ##########

util_programs = clear_stats agent_control verify-agent-conf wazuh-regex parallel-regex

$(util_programs): $(BUILD_LIBS)

.PHONY: utils
utils: ${util_programs}

util_c := $(wildcard util/*.c)
util_o := $(util_c:.c=.o)

util/%.o: util/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./util -DARGV0=\"utils\" -c $^ -o $@

clear_stats: util/clear_stats.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

verify-agent-conf: util/verify-agent-conf.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

agent_control: util/agent_control.o addagent/validate.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

wazuh-regex: util/wazuh-regex.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

parallel-regex: util/parallel-regex.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### rootcheck #####

rootcheck_c := $(wildcard rootcheck/*.c)
rootcheck_o := $(rootcheck_c:.c=.o)
rootcheck_o_lib := $(filter-out rootcheck/rootcheck-config.o, ${rootcheck_o})
rootcheck_o_cmd := $(filter-out rootcheck/config.o, ${rootcheck_o})


rootcheck/%.o: rootcheck/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"rootcheck\" -c $^ -o $@

librootcheck.a: ${rootcheck_o_lib}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


#### FIM ######

wazuh-syscheckd: librootcheck.a libwazuh.a ${WAZUHEXT_LIB} build_shared_modules
	cd syscheckd && mkdir -p build && cd build && cmake ${SYSCHECK_OS} ${CMAKE_OPTS} -DCMAKE_C_FLAGS="${DEFINES} -pipe -Wall -Wextra -std=gnu99" ${SYSCHECK_TEST} ${SYSCHECK_RELEASE_TYPE} .. && ${MAKE}

#### Monitor #######

monitor_c := $(wildcard monitord/*.c)
monitor_o := $(monitor_c:.c=.o)

monitord/%.o: monitord/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-monitord\" -c $< -o $@

wazuh-monitord: ${monitor_o} os_maild/sendcustomemail.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### reportd #######

report_c := reportd/report.c
report_o := $(report_c:.c=.o)

reportd/%.o: reportd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-reportd\" -c $^ -o $@

wazuh-reportd: ${report_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### os_auth #######

os_auth_c := ${wildcard os_auth/*.c}
os_auth_o := $(os_auth_c:.c=.o)

os_auth/%.o: os_auth/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./os_auth -DARGV0=\"wazuh-authd\" -c $^ -o $@

agent-auth: addagent/validate.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

wazuh-authd: addagent/validate.o os_auth/main-server.o os_auth/local-server.o os_auth/ssl.o os_auth/check_cert.o os_auth/config.o os_auth/authcom.o os_auth/auth.o os_auth/key_request.o os_auth/generate_cert.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### integratord #####

integrator_c := ${wildcard os_integrator/*.c}
integrator_o := $(integrator_c:.c=.o)

os_integrator/%.o: os_integrator/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS}  -I./os_integrator -DARGV0=\"wazuh-integratord\" -c $^ -o $@

wazuh-integratord: ${integrator_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### analysisd #####

cdb_c := ${wildcard analysisd/cdb/*.c}
cdb_o := $(cdb_c:.c=.o)
all_analysisd_o += ${cdb_o}
all_analysisd_libs += cdb.a

analysisd/cdb/%.o: analysisd/cdb/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/cdb -c $^ -o $@

cdb.a: ${cdb_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


alerts_c := ${wildcard analysisd/alerts/*.c}
alerts_o := $(alerts_c:.c=.o)
all_analysisd_o += ${alerts_o}
all_analysisd_libs += alerts.a

analysisd/alerts/%.o: analysisd/alerts/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/alerts -c $^ -o $@

alerts.a: ${alerts_o}
	${OSSEC_LINK} $@ $^

decoders_c := ${wildcard analysisd/decoders/*.c} ${wildcard analysisd/decoders/plugins/*.c} ${wildcard analysisd/compiled_rules/*.c}
decoders_o := $(decoders_c:.c=.o)
## XXX Nasty hack
decoders_test_o := $(decoders_c:.c=-test.o)
decoders_live_o := $(decoders_c:.c=-live.o)

all_analysisd_o += ${decoders_o} ${decoders_test_o} ${decoders_live_o}
all_analysisd_libs += decoders.a decoders-test.a decoders-live.a


analysisd/decoders/%-test.o: analysisd/decoders/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/decoders/%-live.o: analysisd/decoders/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/decoders/plugins/%-test.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/plugins/%-live.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/compiled_rules.h: analysisd/compiled_rules/.function_list analysisd/compiled_rules/register_rule.sh
	./analysisd/compiled_rules/register_rule.sh build

analysisd/compiled_rules/%-test.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/%-live.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

decoders-live.a: ${decoders_live_o}
	${OSSEC_LINK} $@ $^

decoders-test.a: ${decoders_test_o}
	${OSSEC_LINK} $@ $^

format_c := ${wildcard analysisd/format/*.c}
format_o := ${format_c:.c=.o}
all_analysisd_o += ${format_o}

analysisd/format/%.o: analysisd/format/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

output_c := ${wildcard analysisd/output/*c}
output_o := ${output_c:.c=.o}
all_analysisd_o += ${output_o}

analysisd/output/%.o: analysisd/output/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd_c := ${filter-out analysisd/logmsg.c, ${filter-out analysisd/analysisd.c, ${filter-out analysisd/testrule.c, ${filter-out analysisd/makelists.c, ${wildcard analysisd/*.c}}}}}
analysisd_o := ${analysisd_c:.c=.o}
all_analysisd_o += ${analysisd_o}

analysisd_test_o := $(analysisd_o:.o=-test.o)
analysisd_live_o := $(analysisd_o:.o=-live.o)
all_analysisd_o += ${analysisd_test_o} ${analysisd_live_o} analysisd/testrule-test.o analysisd/analysisd-live.o analysisd/analysisd-test.o analysisd/makelists-live.o

analysisd/%-live.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-analysisd\" -I./analysisd -c $< -o $@

analysisd/%-test.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"wazuh-analysisd\" -I./analysisd -c $< -o $@

wazuh-logtest-legacy: ${analysisd_test_o} ${output_o} ${format_o} analysisd/testrule-test.o analysisd/analysisd-test.o alerts.a cdb.a decoders-test.a
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

wazuh-analysisd: ${analysisd_live_o} analysisd/analysisd-live.o ${output_o} ${format_o} alerts.a cdb.a decoders-live.a analysisd/logmsg.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

### wazuh-modulesd ##

wmodulesd_c := wazuh_modules/main.c
wmodulesd_o := $(wmodulesd_c:.c=.o)

ifeq (${TARGET},server)
ifeq (,$(filter ${DISABLE_JEMALLOC},YES yes y Y 1))
	MODULESD_LDFLAGS=-L${EXTERNAL_JEMALLOC}lib -ljemalloc
endif
endif

wazuh-modulesd: ${wmodulesd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} ${MODULESD_LDFLAGS} -o $@

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

wpython: install_dependencies install_framework install_api install_mitre

build_python:
ifeq (,${INSTALLDIR})
	$(error INSTALLDIR undefined. Run "${MAKE} TARGET=server INSTALLDIR=/path" to build python from sources)
endif

ifeq (,$(wildcard ${EXTERNAL_CPYTHON}/python))
	export WPATH_LIB="'\$$\$$ORIGIN/../../../lib'" && export SOURCE_PATH=${ROUTE_PATH} && export WAZUH_FFI_PATH=${EXTERNAL_LIBFFI} && export LD_LIBRARY_PATH=${ROUTE_PATH} && cd ${EXTERNAL_CPYTHON} && ./configure --prefix="${WPYTHON_DIR}" --libdir="${WPYTHON_DIR}/lib" --enable-shared --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LDFLAGS="${ARCH_FLAGS} -L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'\$$\$$ORIGIN/../../../lib',--disable-new-dtags" CPPFLAGS="-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}" $(CPYTHON_FLAGS) && ${MAKE}
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

install_mitre: install_python
	cd ../tools/mitre && ${WPYTHON_DIR}/bin/python3 mitredb.py -d ${INSTALLDIR}/var/db/mitre.db

####################
#### test ##########
####################
CFLAGS_TEST=-g -O0 --coverage -DWAZUH_UNIT_TESTING
# Use sanitizers only on linux
ifneq (${TARGET},winagent)
ifeq (${uname_S},Linux)
CFLAGS_TEST+= -fsanitize=address -fsanitize=undefined
endif
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

unit_tests/wrappers/macos/%.o: unit_tests/wrappers/macos/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/macos/libc/%.o: unit_tests/wrappers/macos/libc/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/posix/%.o: unit_tests/wrappers/posix/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/%.o: unit_tests/wrappers/wazuh/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_crypto/%.o: unit_tests/wrappers/wazuh/os_crypto/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_execd/%.o: unit_tests/wrappers/wazuh/os_execd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_net/%.o: unit_tests/wrappers/wazuh/os_net/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_regex/%.o: unit_tests/wrappers/wazuh/os_regex/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/shared/%.o: unit_tests/wrappers/wazuh/shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/syscheckd/%.o: unit_tests/wrappers/wazuh/syscheckd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/wazuh_db/%.o: unit_tests/wrappers/wazuh/wazuh_db/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/wazuh_modules/%.o: unit_tests/wrappers/wazuh/wazuh_modules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/monitord/%.o: unit_tests/wrappers/wazuh/monitord/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/os_auth/%.o: unit_tests/wrappers/wazuh/os_auth/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/addagent/%.o: unit_tests/wrappers/wazuh/addagent/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/config/%.o: unit_tests/wrappers/wazuh/config/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/windows/%.o: unit_tests/wrappers/windows/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/windows/libc/%.o: unit_tests/wrappers/windows/libc/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/remoted/%.o: unit_tests/wrappers/wazuh/remoted/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/wazuh/analysisd/%.o: unit_tests/wrappers/wazuh/analysisd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

.PHONY: test

###################
#### Rule Tests ###
###################

test-rules:
	( cd ../ruleset/testing && sudo python runtests.py)

####################
#### windows #######
####################

win32/version-dll.o: win32/version.rc
	${OSSEC_WINDRES} ${WIN_BUILD_VERSION} ${WIN_BUILD_TYPE} -DVER_TYPE=VFT_DLL -i $< -o $@

win32/version-app.o: win32/version.rc
	${OSSEC_WINDRES} ${WIN_BUILD_VERSION} ${WIN_BUILD_TYPE} -DVER_TYPE=VFT_APP -i $< -o $@

# For security reasons, all executables must have a manifest
# except those .exe files that aren't distributed in the final signed .msi

win32/ui_resource.o: win32/ui/win32ui.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/auth_resource.o: win32/agent-auth.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/wazuh_agent_resource.o: win32/wazuh-agent.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/manage_agents_resource.o: win32/manage_agents.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/restart_wazuh_resource.o: win32/restart-wazuh.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/route_null_resource.o: win32/route-null.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/netsh_resource.o: win32/netsh.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/wazuh_agent_eventchannel_resource.o: win32/wazuh-agent-eventchannel.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/icon.o: win32/icofile.rc
	${OSSEC_WINDRES} -i $< -o $@

win32_c := $(wildcard win32/*.c)
win32_o := $(win32_c:.c=.o)

win32/%.o: win32/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-agent\" -c $^ -o $@

win32/%_rk.o: win32/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -UOSSECHIDS -DARGV0=\"wazuh-agent\" -c $^ -o $@

win32_ui_c := $(wildcard win32/ui/*.c)
win32_ui_o := $(win32_ui_c:.c=.o)

win32/ui/%.o: win32/ui/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -UOSSECHIDS -DARGV0=\"wazuh-win32ui\" -c $^ -o $@

win32/wazuh-agent.exe: win32/wazuh_agent_resource.o win32/version-app.o win32/icon.o win32/win_agent.o win32/win_service.o win32/win_utils.o os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.o ${rootcheck_o} $(filter-out wazuh_modules/main.o, ${wmodulesd_o}) $(filter-out client-agent/main.o, $(filter-out client-agent/agentd.o, $(filter-out client-agent/event-forward.o, ${client_agent_o}))) $(filter-out logcollector/main.o, ${os_logcollector_o}) $(filter-out os_execd/main.o, ${os_execd_o}) active-response/active_responses.o monitord/rotate_log.o monitord/compress_log.o
	${OSSEC_CCBIN} -DARGV0=\"wazuh-agent\" -DOSSECHIDS ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} ${DBSYNC_LIB} ${RSYNC_LIB} -lwazuh-syscheckd -l:libfimdb.lib libwazuh.a -o $@

win32/wazuh-agent-eventchannel.exe: win32/wazuh_agent_eventchannel_resource.o win32/version-app.o win32/icon.o win32/win_agent.o win32/win_service.o win32/win_utils.o os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.o ${rootcheck_o} $(filter-out wazuh_modules/main.o, ${wmodulesd_o}) $(filter-out client-agent/main.o, $(filter-out client-agent/agentd.o, $(filter-out client-agent/event-forward.o, ${client_agent_o}))) $(filter-out logcollector/main-event.o, ${os_logcollector_eventchannel_o}) $(filter-out os_execd/main.o, ${os_execd_o}) active-response/active_responses.o monitord/rotate_log.o monitord/compress_log.o
	${OSSEC_CCBIN} -DARGV0=\"wazuh-agent\" -DOSSECHIDS -DEVENTCHANNEL_SUPPORT ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} ${DBSYNC_LIB} ${RSYNC_LIB} -lwazuh-syscheckd-event -l:libfimdb.lib libwazuh.a -lwevtapi -o $@

win32/manage_agents.exe: win32/manage_agents_resource.o win32/version-app.o win32/win_service_rk.o ${addagent_o}
	${OSSEC_CCBIN} -DARGV0=\"manage-agents\" -DMA ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/setup-windows.exe: win32/win_service_rk.o win32/setup-win.o win32/setup-shared.o
	${OSSEC_CCBIN} -DARGV0=\"setup-windows\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/setup-syscheck.exe: win32/win_service_rk.o win32/setup-syscheck.o win32/setup-shared.o
	${OSSEC_CCBIN} -DARGV0=\"setup-syscheck\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/setup-iis.exe: win32/win_service_rk.o win32/setup-iis.o
	${OSSEC_CCBIN} -DARGV0=\"setup-iis\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/ui_resource.o: win32/ui/win32ui.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/auth_resource.o: win32/agent-auth.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/os_win32ui.exe: win32/ui_resource.o win32/version-app.o win32/win_service_rk.o ${win32_ui_o}
	${OSSEC_CCBIN} -DARGV0=\"wazuh-win32ui\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -I./syscheckd/include -mwindows -o $@

win32/agent-auth.exe: win32/auth_resource.o win32/version-app.o win32/win_service_rk.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o addagent/validate.o
	${OSSEC_CCBIN} -DARGV0=\"agent-auth\" -DOSSECHIDS ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -lshlwapi -lwsock32 -lsecur32 -lws2_32 -flto -o $@

win32/restart-wazuh.exe: win32/restart_wazuh_resource.o win32/version-app.o active-response/active_responses.o active-response/restart-wazuh.o shared/cryptography.o shared/dll_load_notify.o shared/debug_op_proc.o shared/time_op.o shared/file_op_proc.o ${WAZUH_LIB} ${WAZUHEXT_LIB}
	${OSSEC_CCBIN} -DARGV0=\"restart-wazuh\" ${AR_LDFLAGS} $^ -lwintrust -lpsapi -lcrypt32 -lshlwapi -lmpr -o $@

win32/route-null.exe: win32/route_null_resource.o win32/version-app.o active-response/active_responses.o active-response/route-null.o shared/cryptography.o shared/dll_load_notify.o shared/debug_op_proc.o shared/time_op.o shared/file_op_proc.o ${WAZUH_LIB} ${WAZUHEXT_LIB}
	${OSSEC_CCBIN} -DARGV0=\"route-null\" ${AR_LDFLAGS} $^ -lwintrust -lpsapi -lcrypt32 -lshlwapi -lmpr -o $@

win32/netsh.exe: win32/netsh_resource.o win32/version-app.o active-response/active_responses.o active-response/netsh.o shared/cryptography.o shared/dll_load_notify.o shared/debug_op_proc.o shared/time_op.o shared/file_op_proc.o ${WAZUH_LIB} ${WAZUHEXT_LIB}
	${OSSEC_CCBIN} -DARGV0=\"netsh\" ${AR_LDFLAGS} $^ -lwintrust -lpsapi -lcrypt32 -lshlwapi -lmpr -o $@


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
	rm -rf $(EXTERNAL_LIBBPF)build
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
	rm -f $(BUILD_AGENT)
	rm -f $(BUILD_LIBS)
	rm -f ${os_zlib_o}
	rm -f ${os_xml_o}
	rm -f ${os_regex_o}
	rm -f ${os_net_o}
	rm -f ${shared_o} shared/debug_op_proc.o shared/file_op_proc.o
	rm -f ${config_o}
	rm -f ${os_maild_o}
	rm -f ${crypto_o}
	rm -f ${os_csyslogd_o}
	rm -f ${os_dbd_o}
	rm -f ${os_agentlessd_o}
	rm -f ${os_execd_o}
	rm -f ${os_logcollector_o} ${os_logcollector_eventchannel_o}
	rm -f ${remoted_o}
	rm -f ${report_o}
	rm -f ${client_agent_o}
	rm -f ${addagent_o}
	rm -f ${active_response_o} ${active_response_programs} firewall-drop
	rm -f ${util_o} ${util_programs}
	rm -f ${rootcheck_o} librootcheck.a
	rm -f ${monitor_o}
	rm -f ${os_auth_o}
	rm -f ${all_analysisd_o} ${all_analysisd_libs} analysisd/compiled_rules/compiled_rules.h analysisd/logmsg.o
	rm -f ${integrator_o}
	rm -f ${wmodulesd_o} ${wmodules_o} $(wildcard wazuh_modules/agent_upgrade/agent/*.o)
	rm -f ${wdb_o}
	rm -f wazuh_db/*.o
	rm -f wazuh_db/helpers/*.o
	rm -f ${SELINUX_MODULE}
	rm -f ${SELINUX_POLICY}
	rm -f $(WAZUH_LIB)
	rm -rf $(DBSYNC)build
	rm -rf $(RSYNC)build
	rm -rf $(SYSCOLLECTOR)build
	rm -rf $(SHARED_MODULES)utils/flatbuffers/include/
	rm -rf $(wildcard $(VULNERABILITY_SCANNER)include/*_generated.h)
	rm -rf $(SYSINFO)build
	rm -rf $(SYSCHECK)build
	rm -rf ${SHARED_MODULES}http-request/build
	rm -rf build
	rm -rf libwazuhext
	rm -rf libstdc++.so.6
	rm -rf libgcc_s.so.1
	rm -f libwazuh.a
	rm -f shared/*.o


clean-unit-tests:
	rm -f ${wrappers_syscheck_o}
	rm -f ${wrappers_shared_o}
	rm -f ${wrappers_common_o}
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
	rm -f ${wrappers_macos_o}
	rm -f ${wrappers_macos_libc_o}
	rm -f ${wrappers_macos_posix_o}
	rm -f ${wrappers_posix_o}
	rm -f ${wrappers_wazuh_o}
	rm -f ${wrappers_wazuh_os_crypto_o}
	rm -f ${wrappers_wazuh_os_execd_o}
	rm -f ${wrappers_wazuh_os_net_o}
	rm -f ${wrappers_wazuh_os_regex_o}
	rm -f ${wrappers_wazuh_os_xml_o}
	rm -f ${wrappers_wazuh_shared_o}
	rm -f ${wrappers_wazuh_syscheckd_o}
	rm -f ${wrappers_wazuh_wazuh_db_o}
	rm -f ${wrappers_wazuh_wazuh_modules_o}
	rm -f ${wrappers_wazuh_monitord_o}
	rm -f ${wrappers_wazuh_os_auth_o}
	rm -f ${wrappers_wazuh_addagent_o}
	rm -f ${wrappers_wazuh_config_o}
	rm -f ${wrappers_windows_o}
	rm -f ${wrappers_windows_lib_o}
	rm -f ${wrappers_windows_posix_o}
	rm -f ${wrappers_client_agent_o}
	rm -f ${wrappers_wazuh_remoted_o}
	rm -f ${wrappers_wazuh_analysisd_o}
	rm -f ${wrappers_logcollector_o}
	rm -f ${wrappers_macos_o}
	rm -f ${wrappers_data_provider_o}

clean-framework:
	${MAKE} -C ../framework clean

clean-windows:
	rm -f libwazuh.a
	rm -f libwazuhshared.*
	rm -f libwazuhext.*
	rm -f wazuh_modules/syscollector/*.o wazuh_modules/syscollector/*.obj
	rm -f win32/LICENSE.txt
	rm -f win32/help_win.txt
	rm -f win32/internal_options.conf
	rm -f win32/default-local_internal_options.conf
	rm -f win32/default-ossec.conf
	rm -f win32/restart-ossec.cmd
	rm -f win32/route-null.cmd
	rm -f win32/route-null-2012.cmd
	rm -f win32/netsh.cmd
	rm -f win32/netsh-win-2016.cmd
	rm -f win32/default-ossec-pre6.conf
	rm -f win32/restart-wazuh.exe
	rm -f win32/route-null.exe
	rm -f win32/netsh.exe
	rm -f ${win32_o} ${win32_ui_o} win32/win_service_rk.o
	rm -f win32/icon.o win32/resource.o
	rm -f ${WINDOWS_BINS}
	rm -f win32/wazuh-agent-*.exe
	rm -f win32/libwinpthread-1.dll
	rm -f win32/*.o
	rm -f win32/version-*.o
	rm -f win32/VERSION.json
	rm -f win32/libstdc++-6.dll
	rm -f win32/libgcc_s_dw2-1.dll
	rm -f win32/libgcc_s_sjlj-1.dll

clean-config:
	rm -f ../etc/ossec.mc
	rm -f Config.OS
