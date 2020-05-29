# Copyright (C) 2015-2020, Wazuh Inc.
# TODO: mysql and postgresql?
#
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
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
EXTERNAL_CPYTHON=external/cpython/
EXTERNAL_MSGPACK=external/msgpack/
EXTERNAL_BZIP2=external/bzip2/
ifneq (${TARGET},winagent)
EXTERNAL_PROCPS=external/procps/
EXTERNAL_LIBDB=external/libdb/build_unix/
endif
MAXAGENTS?=100000
# XXX Becareful NO EXTRA Spaces here
PREFIX?=/var/ossec
PG_CONFIG?=pg_config
MY_CONFIG?=mysql_config
PRELUDE_CONFIG?=libprelude-config
OSSEC_GROUP?=ossec
OSSEC_USER?=ossec
OSSEC_USER_MAIL?=ossecm
OSSEC_USER_REM?=ossecr
SHARED=so
SELINUX_MODULE=selinux/wazuh.mod
SELINUX_ENFORCEMENT=selinux/wazuh.te
SELINUX_POLICY=selinux/wazuh.pp

USE_PRELUDE?=no
USE_ZEROMQ?=no
USE_GEOIP?=no
USE_INOTIFY=no
USE_BIG_ENDIAN=no
USE_AUDIT=no
USE_FRAMEWORK_LIB=no
MINGW_HOST=unknown
USE_MSGPACK_OPT=yes

DISABLE_SHARED?=no
DISABLE_SYSC?=no
DISABLE_CISCAT?=no

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

DEFINES=-DMAX_AGENTS=${MAXAGENTS} -DOSSECHIDS
DEFINES+=-DDEFAULTDIR=\"${PREFIX}\"
DEFINES+=-DUSER=\"${OSSEC_USER}\"
DEFINES+=-DREMUSER=\"${OSSEC_USER_REM}\"
DEFINES+=-DGROUPGLOBAL=\"${OSSEC_GROUP}\"
DEFINES+=-DMAILUSER=\"${OSSEC_USER_MAIL}\"

ifneq (${TARGET},winagent)
		DEFINES+=-D${uname_S}
ifeq (${uname_S},Linux)
		DEFINES+=-DINOTIFY_ENABLED -D_XOPEN_SOURCE=600 -D_GNU_SOURCE
#		DEFINES+=-DUSE_MAGIC
		OSSEC_CFLAGS+=-pthread -I${EXTERNAL_LIBDB}
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		OSSEC_LIBS+=-lrt -ldl -lm
#		OSSEC_LDFLAGS+=-lmagic
		OSSEC_LDFLAGS+=-pthread -lrt -ldl
#		OSSEC_LDFLAGS+=-lmagic
		OSSEC_CFLAGS+=-Wl,--start-group
		USE_AUDIT=yes
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
		OSSEC_CFLAGS+=-I$(EXTERNAL_AUDIT)lib
endif
else
ifeq (${uname_S},AIX)
		DEFINES+=-DAIX -D__unix
		DEFINES+=-DHIGHFIRST
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		PATH:=${PATH}:/usr/vac/bin
		CC=gcc
else
ifeq (${uname_S},SunOS)
		DEFINES+=-DSOLARIS
		DEFINES+=-DHIGHFIRST
		DEFINES+=-D_REENTRANT
ifneq (${uname_P},sparc)
ifneq ($(uname_R),5.10)
		OSSEC_LDFLAGS+=-z relax=secadj
else
		OSSEC_CFLAGS+=-DMSGPACK_ZONE_ALIGN=8
endif
endif
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		OSSEC_LIBS+=-lsocket -lnsl -lresolv -lrt -lpthread
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
		SHARED=dylib
		OSSEC_LIBS+=-framework Security
else
ifeq (${uname_S},FreeBSD)
		DEFINES+=-DFreeBSD
		OSSEC_CFLAGS+=-pthread -I/usr/local/include
		OSSEC_LDFLAGS+=-pthread
		OSSEC_LDFLAGS+=-L/usr/local/lib
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
else
ifeq (${uname_S},NetBSD)
		DEFINES+=-DNetBSD
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
else
ifeq (${uname_S},OpenBSD)
		DEFINES+=-DOpenBSD
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		OSSEC_LDFLAGS+=-L/usr/local/lib
		OSSEC_LDFLAGS+=-Wl,-zorigin '-Wl,-rpath,$$ORIGIN/../lib'
else
ifeq (${uname_S},HP-UX)
		DEFINES+=-DHPUX
		DEFINES+=-D_XOPEN_SOURCE_EXTENDED
		DEFINES+=-DHIGHFIRST
		DEFINES+=-DOS_BIG_ENDIAN
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-lrt
ifeq (,$(filter ${DISABLE_SHARED},YES yes y Y 1))
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
endif
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		PATH:=${PATH}:/usr/local/bin
		CC=gcc
		INSTALL=/usr/local/coreutils/bin/install
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
		SHARED=dll
		DEFINES_EVENTCHANNEL=-D_WIN32_WINNT=0x600
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
endif # winagent

ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
	DEFINES+=-DENABLE_SYSC
endif

ifeq (,$(filter ${DISABLE_CISCAT},YES yes y Y 1))
	DEFINES+=-DENABLE_CISCAT
endif

ifeq (,$(filter ${DISABLE_SHARED},YES yes y Y 1))
	DEFINES+=-DENABLE_SHARED
endif

ifneq (,$(filter ${DEBUGAD},YES yes y Y 1))
	DEFINES+=-DDEBUGAD
endif

ifneq (,$(filter ${DEBUG},YES yes y Y 1))
	OSSEC_CFLAGS+=-g
else
	OSSEC_CFLAGS+=-DNDEBUG
	OFLAGS+=-O2
endif #DEBUG

OSSEC_CFLAGS+=${OFLAGS}
OSSEC_LDFLAGS+=${OFLAGS}

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
OSSEC_CFLAGS+=-I./ -I./headers/ -I${EXTERNAL_OPENSSL}include -I$(EXTERNAL_JSON) -I${EXTERNAL_LIBYAML}include -I${EXTERNAL_CURL}include -I${EXTERNAL_MSGPACK}include -I${EXTERNAL_BZIP2}

OSSEC_CFLAGS += ${CFLAGS}
OSSEC_LDFLAGS += ${LDFLAGS}
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

endif #winagent


OSSEC_CC      =${QUIET_CC}${MING_BASE}${CC}
OSSEC_CCBIN   =${QUIET_CCBIN}${MING_BASE}${CC}
OSSEC_SHARED  =${QUIET_CCBIN}${MING_BASE}${CC} -shared
OSSEC_LINK    =${QUIET_LINK}${MING_BASE}ar -crus
OSSEC_RANLIB  =${QUIET_RANLIB}${MING_BASE}ranlib
OSSEC_WINDRES =${QUIET_CCBIN}${MING_BASE}windres


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
	#LDFLAGS+=-L/usr/local/lib -I/usr/local/include -lzmq -lczmq
	OSSEC_LIBS+=-lzmq -lczmq
endif # USE_ZEROMQ

ifneq (,$(filter ${USE_GEOIP},YES auto yes y Y 1))
	DEFINES+=-DLIBGEOIP_ENABLED
	OSSEC_LIBS+=-lGeoIP
endif # USE_GEOIP


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
	@echo "   make V=yes                   Display full compiler messages. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DEBUG=yes               Build with symbols and without optimization. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DEBUGAD=yes             Enables extra debugging logging in ossec-analysisd. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make PREFIX=/path            Install OSSEC to '/path'. Defaults to /var/ossec"
	@echo "   make MAXAGENTS=NUMBER        Set the number of maximum agents to NUMBER. Defaults to 2048"
	@echo "   make ONEWAY=yes              Disables manager's ACK towards agent. It allows connecting agents without backward connection from manager. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make CLEANFULL=yes           Makes the alert mailing subject clear in the format: '<location> - <level> - <description>'. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make RESOURCES_URL           Set the Wazuh resources URL"
	@echo "   make USE_ZEROMQ=yes          Build with zeromq support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_PRELUDE=yes         Build with prelude support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_INOTIFY=yes         Build with inotify support. Allowed values are auto, 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make BIG_ENDIAN=yes          Build with big endian support. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_SELINUX=yes         Build with SELinux policies. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_AUDIT=yes           Build with audit service support. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_FRAMEWORK_LIB=yes   Use external SQLite library for the framework. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make USE_MSGPACK_OPT=yes     Use default architecture for building msgpack library. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make OFLAGS=-Ox              Overrides optimization level"
	@echo "   make DISABLE_SHARED=yes      Not to build the Wazuh shared library (for unsupported systems). Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DISABLE_SYSC=yes        Not to build the Syscollector module (for unsupported systems). Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make DISABLE_CISCAT=yes      Not to build the CIS-CAT module (for unsupported systems). Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
	@echo "   make OPTIMIZE_CPYTHON=yes    When PREFIX points to other directory than default, the python interpreter is rebuilt, enable this flag to optimize the process. Allowed values are 1, yes, YES, y and Y, otherwise, the flag is ignored"
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
	@echo "   make OSSEC_GROUP=ossec       Set ossec group"
	@echo "   make OSSEC_USER=ossec        Set ossec user"
	@echo "   make OSSEC_USER_MAIL=ossecm  Set ossec user mail"
	@echo "   make OSSEC_USER_REM=ossecr   Set ossec user rem"
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
	@echo "    PREFIX:             ${PREFIX}"
	@echo "    MAXAGENTS:          ${MAXAGENTS}"
	@echo "    DATABASE:           ${DATABASE}"
	@echo "    ONEWAY:             ${ONEWAY}"
	@echo "    CLEANFULL:          ${CLEANFULL}"
	@echo "    RESOURCES_URL:      ${RESOURCES_URL}"
	@echo "    DISABLE_SHARED:     ${DISABLE_SHARED}"
	@echo "User settings:"
	@echo "    OSSEC_GROUP:        ${OSSEC_GROUP}"
	@echo "    OSSEC_USER:         ${OSSEC_USER}"
	@echo "    OSSEC_USER_MAIL:    ${OSSEC_USER_MAIL}"
	@echo "    OSSEC_USER_REM:     ${OSSEC_USER_REM}"
	@echo "USE settings:"
	@echo "    USE_ZEROMQ:         ${USE_ZEROMQ}"
	@echo "    USE_GEOIP:          ${USE_GEOIP}"
	@echo "    USE_PRELUDE:        ${USE_PRELUDE}"
	@echo "    USE_INOTIFY:        ${USE_INOTIFY}"
	@echo "    USE_BIG_ENDIAN:     ${USE_BIG_ENDIAN}"
	@echo "    USE_SELINUX:        ${USE_SELINUX}"
	@echo "    USE_AUDIT:          ${USE_AUDIT}"
	@echo "    USE_FRAMEWORK_LIB:  ${USE_FRAMEWORK_LIB}"
	@echo "    DISABLE_SHARED:     ${DISABLE_SHARED}"
	@echo "    DISABLE_SYSC:       ${DISABLE_SYSC}"
	@echo "    DISABLE_CISCAT:     ${DISABLE_CISCAT}"
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

BUILD_SERVER+=ossec-maild -
BUILD_SERVER+=ossec-csyslogd -
BUILD_SERVER+=ossec-agentlessd -
BUILD_SERVER+=ossec-execd -
BUILD_SERVER+=ossec-logcollector -
BUILD_SERVER+=ossec-remoted
BUILD_SERVER+=ossec-agentd
BUILD_SERVER+=manage_agents
BUILD_SERVER+=utils
BUILD_SERVER+=ossec-syscheckd
BUILD_SERVER+=ossec-monitord
BUILD_SERVER+=ossec-reportd
BUILD_SERVER+=ossec-authd
BUILD_SERVER+=ossec-analysisd
BUILD_SERVER+=ossec-logtest
BUILD_SERVER+=ossec-makelists
BUILD_SERVER+=ossec-dbd -
BUILD_SERVER+=ossec-integratord
BUILD_SERVER+=wazuh-modulesd
BUILD_SERVER+=wazuh-db
ifneq (,$(filter ${USE_FRAMEWORK_LIB},YES yes y Y 1))
BUILD_SERVER+=wazuh-framework
endif

BUILD_AGENT+=ossec-agentd
BUILD_AGENT+=agent-auth
BUILD_AGENT+=ossec-logcollector
BUILD_AGENT+=ossec-syscheckd
BUILD_AGENT+=ossec-execd
BUILD_AGENT+=manage_agents
BUILD_AGENT+=wazuh-modulesd

.PHONY: server local hybrid agent selinux

ifeq (${MAKECMDGOALS},server)
$(error Do not use 'server' directly, use 'TARGET=server')
endif
server: external
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},local)
$(error Do not use 'local' directly, use 'TARGET=local')
endif
local: external
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},hybrid)
$(error Do not use 'hybrid' directly, use 'TARGET=hybrid')
endif
hybrid: external
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},agent)
$(error Do not use 'agent' directly, use 'TARGET=agent')
endif
agent: external
	${MAKE} ${BUILD_AGENT}

ifneq (,$(filter ${USE_SELINUX},YES yes y Y 1))
server local hybrid agent: selinux
endif

selinux: $(SELINUX_POLICY)

$(SELINUX_POLICY): $(SELINUX_MODULE)
	semodule_package -o $@ -m $?

$(SELINUX_MODULE): $(SELINUX_ENFORCEMENT)
	checkmodule -M -m -o $@ $?

test_programs = tap_wazuhdb_op tap_os_crypto tap_os_net tap_os_regex tap_shared tap_os_zlib tap_os_xml tap_fluentd_forwarder

WINDOWS_BINS:=win32/ossec-agent.exe win32/ossec-agent-eventchannel.exe win32/ossec-rootcheck.exe win32/manage_agents.exe win32/setup-windows.exe win32/setup-syscheck.exe win32/setup-iis.exe win32/add-localfile.exe win32/os_win32ui.exe win32/agent-auth.exe

ifeq (${MAKECMDGOALS},winagent)
$(error Do not use 'winagent' directly, use 'TARGET=winagent')
endif
.PHONY: winagent
winagent: external win32/libwinpthread-1.dll wazuh_modules/syscollector/syscollector_win_ext.dll
	${MAKE} ${WINDOWS_BINS} CFLAGS="-DCLIENT -D_POSIX_C_SOURCE -DWIN32 -DPSAPI_VERSION=1" LIBS="-lwsock32 -lwevtapi -lshlwapi -lcomctl32 -ladvapi32 -lkernel32 -lpsapi -lgdi32 -liphlpapi -lws2_32 -lcrypt32"
	cd win32/ && ./unix2dos.pl ossec.conf > default-ossec.conf
	cd win32/ && ./unix2dos.pl ossec-pre6.conf > default-ossec-pre6.conf
	cd win32/ && ./unix2dos.pl help.txt > help_win.txt
	cd win32/ && ./unix2dos.pl ../../etc/internal_options.conf > internal_options.conf
	cd win32/ && ./unix2dos.pl ../../etc/local_internal_options-win.conf > default-local_internal_options.conf
	cd win32/ && ./unix2dos.pl ../../LICENSE > LICENSE.txt
	cd win32/ && ./unix2dos.pl ../../active-response/win/route-null.cmd > route-null.cmd
	cd win32/ && ./unix2dos.pl ../../active-response/win/route-null-2012.cmd > route-null-2012.cmd
	cd win32/ && ./unix2dos.pl ../../active-response/win/netsh.cmd > netsh.cmd
	cd win32/ && ./unix2dos.pl ../../active-response/win/netsh-win-2016.cmd > netsh-win-2016.cmd
	cd win32/ && ./unix2dos.pl ../../active-response/win/restart-ossec.cmd > restart-ossec.cmd
	cd win32/ && ./unix2dos.pl ../VERSION > VERSION
	cd win32/ && ./unix2dos.pl ../REVISION > REVISION
	cd win32/ && makensis ossec-installer.nsi

win32/libwinpthread-1.dll: ${WIN_PTHREAD_LIB}
	cp $< $@

####################
#### External ######
####################

ZLIB_LIB    = $(EXTERNAL_ZLIB)/libz.a
OPENSSL_LIB = $(EXTERNAL_OPENSSL)libssl.a
CRYPTO_LIB = $(EXTERNAL_OPENSSL)libcrypto.a

SQLITE_LIB  = $(EXTERNAL_SQLITE)libsqlite3.a
JSON_LIB    = $(EXTERNAL_JSON)libcjson.a
PROCPS_LIB  = $(EXTERNAL_PROCPS)/libproc.a
DB_LIB      = $(EXTERNAL_LIBDB).libs/libdb-6.2.a
LIBYAML_LIB = $(EXTERNAL_LIBYAML)src/.libs/libyaml.a
LIBCURL_LIB = $(EXTERNAL_CURL)lib/.libs/libcurl.a
AUDIT_LIB = $(EXTERNAL_AUDIT)lib/.libs/libaudit.a
LIBFFI_LIB = $(EXTERNAL_LIBFFI)$(TARGET)/.libs/libffi.a
MSGPACK_LIB = $(EXTERNAL_MSGPACK)libmsgpack.a
BZIP2_LIB   = $(EXTERNAL_BZIP2)libbz2.a

EXTERNAL_LIBS := $(JSON_LIB) $(ZLIB_LIB) $(OPENSSL_LIB) $(CRYPTO_LIB) $(SQLITE_LIB) $(LIBYAML_LIB)

ifneq (${TARGET},winagent)
EXTERNAL_LIBS += $(MSGPACK_LIB)
ifneq (${TARGET},agent)
EXTERNAL_LIBS += $(LIBCURL_LIB) $(LIBFFI_LIB) $(BZIP2_LIB)
endif
ifeq (${uname_S},Linux)
ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
EXTERNAL_LIBS += ${AUDIT_LIB}
endif

EXTERNAL_LIBS += $(PROCPS_LIB) $(DB_LIB)
endif
endif

.PHONY: external test_external
external: test_external $(EXTERNAL_LIBS)

ifneq (${TARGET},winagent)
ifneq (${TARGET},agent)
external: build_python
endif
endif

test_external:
ifeq ($(wildcard external/*/*),)
	$(error No external directory found. Run "${MAKE} deps" before compiling external libraries)
endif

#### OpenSSL ##########

OPENSSL_FLAGS = enable-weak-ssl-ciphers no-shared

${CRYPTO_LIB}: ${OPENSSL_LIB}

${OPENSSL_LIB}:
ifeq (${TARGET},winagent)
	cd ${EXTERNAL_OPENSSL} && CC=${MING_BASE}${CC} RC=${MING_BASE}windres ./Configure $(OPENSSL_FLAGS) mingw && ${MAKE} build_libs
else
ifeq (${uname_S},Darwin)
	cd ${EXTERNAL_OPENSSL} && ./Configure $(OPENSSL_FLAGS) darwin64-x86_64-cc && ${MAKE} build_libs
else
ifeq (${uname_S},HP-UX)
	cd ${EXTERNAL_OPENSSL} && MAKE=gmake ./Configure $(OPENSSL_FLAGS) hpux-ia64-gcc && ${MAKE} build_libs
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

#### libffi ##########

LIBFFI_FLAGS = "CFLAGS=-fPIC"

${LIBFFI_LIB}:
	cd ${EXTERNAL_LIBFFI} && ./configure $(LIBFFI_FLAGS) && ${MAKE}

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

#### bzip2 ##########

$(BZIP2_LIB):
	cd ${EXTERNAL_BZIP2} && ${MAKE} CFLAGS="-fpic -Wall -O2 -D_FILE_OFFSET_BITS=64" libbz2.a

#### SQLite #########

sqlite_c = ${EXTERNAL_SQLITE}sqlite3.c
sqlite_o = ${EXTERNAL_SQLITE}sqlite3.o

$(SQLITE_LIB): $(sqlite_o)
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

$(sqlite_o): $(sqlite_c)
	${OSSEC_CC} ${OSSEC_CFLAGS} -w -fPIC -c $^ -o $@ -fPIC

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

ifeq (${uname_S},Darwin)
$(EXTERNAL_CURL)Makefile:
	cd $(EXTERNAL_CURL) && ./configure --with-darwinssl --disable-ldap --without-libidn2
else
$(EXTERNAL_CURL)Makefile: $(OPENSSL_LIB)
ifeq (${uname_S},Linux)
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-ldl -lpthread" ./configure --disable-ldap --without-libidn2
else
	cd $(EXTERNAL_CURL) && CPPFLAGS="-fPIC -I${ROUTE_PATH}/${EXTERNAL_OPENSSL}include" LDFLAGS="-L${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LIBS="-lpthread" ./configure --disable-ldap --without-libidn2
endif
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
	cd ${EXTERNAL_LIBDB} && CPPFLAGS=-fPIC ../dist/configure --with-cryptography=no --disable-queue --disable-heap --disable-partition --disable-mutexsupport --disable-replication --disable-verify --disable-statistics
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

################################
#### External dependencies  ####
################################

TAR := tar -xf
GUNZIP := gunzip
CURL := curl -so
space =
space +=
VERSION = $(subst $(space),.,$(wordlist 1,2,$(subst ., ,$(patsubst v%,%,$(shell cat VERSION)))))
RESOURCES_URL := https://packages.wazuh.com/deps/$(VERSION)
CPYTHON := cpython
ifeq (${PREFIX},/var/ossec)
	# Download the Python sources if we are building for any other OS.
ifeq (${uname_S},Linux)
cpu_arch := ${uname_P}
ifneq (,$(filter ${cpu_arch},unknown Unknown))
	cpu_arch := $(shell sh -c 'arch 2>/dev/null || echo not')
endif
ifneq (,$(filter ${cpu_arch},x86_64 amd64))
PRECOMPILED_RES := linux/amd64
else
ifneq (,$(filter ${cpu_arch},i386 i686))
PRECOMPILED_RES := linux/i386
else
ifneq (,$(filter ${cpu_arch},aarch64 arm64))
PRECOMPILED_RES := linux/aarch64
else
ifneq (,$(filter ${cpu_arch},armv8l armv7l arm32 armhf))
PRECOMPILED_RES := linux/arm32
endif
endif
endif
endif
endif
endif


EXTERNAL_RES := cJSON $(CPYTHON) curl libdb libffi libyaml openssl procps sqlite zlib audit-userspace msgpack bzip2
EXTERNAL_DIR :=  $(EXTERNAL_RES:%=external/%)
EXTERNAL_TAR := $(EXTERNAL_RES:%=external/%.tar.gz)

VULN_DETECTOR_DIR := wazuh_modules/vulnerability_detector
MSU_JSON_GZ := $(VULN_DETECTOR_DIR)/msu.json.gz

.PHONY: deps
deps: $(EXTERNAL_TAR) $(MSU_JSON_GZ) $(MSU_JSON_GZ)

external/$(CPYTHON).tar.gz:
ifneq (,$(PRECOMPILED_RES))
	$(CURL) $@ $(RESOURCES_URL)/libraries/$(PRECOMPILED_RES)/$(patsubst external/%,%,$@)
else
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
endif
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)

external/%.tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)

$(MSU_JSON_GZ):
	$(CURL) $@ $(RESOURCES_URL)/vulnerability-detector/windows/$(patsubst $(VULN_DETECTOR_DIR)/%,%,$@)


####################
#### OSSEC Libs ####
####################

ifneq (,$(filter ${DISABLE_SHARED},YES yes y Y 1))
BUILD_LIBS = libwazuh.a $(EXTERNAL_LIBS)
else
WAZUHEXT_LIB = libwazuhext.$(SHARED)
BUILD_LIBS = libwazuh.a $(WAZUHEXT_LIB)
endif

$(BUILD_SERVER) $(BUILD_AGENT) $(WINDOWS_BINS) $(test_programs): $(BUILD_LIBS)

#### os_xml ########

os_xml_c := $(wildcard os_xml/*.c)
os_xml_o := $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

#### os_regex ######

os_regex_c := $(wildcard os_regex/*.c)
os_regex_o := $(os_regex_c:.c=.o)

os_regex/%.o: os_regex/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

#### os_net ##########

os_net_c := $(wildcard os_net/*.c)
os_net_o := $(os_net_c:.c=.o)

os_net/%.o: os_net/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

#### Shared ##########
# Unit tests wrappers
wrappers_common_c := $(wildcard unit_tests/wrappers/*.c)
wrappers_common_o := $(wrappers_common_c:.c=.o)

wrappers_syscheck_c := $(wildcard unit_tests/wrappers/syscheckd/*.c)
wrappers_syscheck_o := $(wrappers_syscheck_c:.c=.o)

wrappers_shared_c := $(wildcard unit_tests/wrappers/shared/*.c)
wrappers_shared_o := $(wrappers_shared_c:.c=.o)

ifneq (,$(filter ${TEST},YES yes y Y 1))
	OSSEC_CFLAGS+=${CFLAGS_TEST}
	# OSSEC_CFLAGS+=${CFLAGS_TEST} -Itests
	OSSEC_LDFLAGS+=${CFLAGS_TEST}
	OSSEC_LIBS+=${LIBS_TEST}

UNIT_TEST_WRAPPERS:=${wrappers_common_o}
ifeq (${TARGET},winagent)
	UNIT_TEST_WRAPPERS+=${wrappers_shared_o}
	UNIT_TEST_WRAPPERS+=${wrappers_syscheck_o}
endif
endif #TEST

shared_c := $(wildcard shared/*.c)
shared_o := $(shared_c:.c=.o)

shared/%.o: shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-remoted\" -c $^ -o $@

#### Wazuh DB ####

wdb_sql := $(wildcard wazuh_db/*.sql)
wdblib_c := $(wildcard wazuh_db/wdb*.c)
wdblib_o := $(wdblib_c:.c=.o) $(wdb_sql:.sql=.o)
wdb_o := wazuh_db/main.o $(wdblib_o:.c=.o) $(wdb_c:.c=.o) $(wdb_sql:.sql=.o)

wazuh_db/schema_%.o: wazuh_db/schema_%.sql
	${QUIET_CC}echo 'const char *'$(word 2, $(subst /, ,$(subst .,_,$<))) '= "'"`cat $< | tr -d \"\n\"`"'";' | ${MING_BASE}${CC} ${OSSEC_CFLAGS} -xc -c -o $@ -

wazuh_db/%.o: wazuh_db/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"wazuh-db\" -c $^ -o $@

wazuh-db: ${wdb_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### Config ##########

config_c := $(wildcard config/*.c)
config_o := $(config_c:.c=.o)

config/%.o: config/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

#### Wazuh modules ##

wmodules_c := $(wildcard wazuh_modules/wm*.c)

ifneq (${TARGET},agent)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/vulnerability_detector/*.c)
endif

ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/syscollector/*.c)
endif

wmodules_o := $(wmodules_c:.c=.o)

wazuh_modules/%.o: wazuh_modules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

ifeq (${TARGET},winagent)
wazuh_modules/syscollector/syscollector_win_ext.dll: wazuh_modules/syscollector/syscollector_win_ext.o
	${OSSEC_SHARED} ${OSSEC_LDFLAGS} $^ -o $@ $(OSSEC_LIBS) $(JSON_LIB) -liphlpapi -lws2_32
endif # DLL for Windows

ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
wazuh_modules/syscollector/%.o: wazuh_modules/syscollector/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@
endif

wmodules_dep := ${wmodules_o} ${wdblib_o}

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

libwazuh.a: ${config_o} ${wmodules_dep} ${crypto_o} ${shared_o} ${os_net_o} ${os_regex_o} ${os_xml_o} ${os_zlib_o} ${UNIT_TEST_WRAPPERS}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

### libwazuhext #########

ifeq (,$(filter ${DISABLE_SHARED},YES yes y Y 1))
ifeq (${uname_S},Darwin)
WAZUH_SHFLAGS=-install_name @rpath/libwazuhext.$(SHARED)

$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $(WAZUH_SHFLAGS) -o $@ -Wl,-all_load $^ -Wl,-noall_load $(OSSEC_LIBS)
else
ifeq (${TARGET}, winagent)
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -static-libgcc -Wl,--export-all-symbols -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
else
ifeq (${uname_P},sparc)
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -mimpure-text -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
else
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
endif
endif
endif

#### os_mail #########

os_maild_c := $(wildcard os_maild/*.c)
os_maild_o := $(os_maild_c:.c=.o)

os_maild/%.o: os_maild/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-maild\" -c $^ -o $@

ossec-maild: ${os_maild_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### os_dbd ##########

os_dbd_c := $(wildcard os_dbd/*.c)
os_dbd_o := $(os_dbd_c:.c=.o)

os_dbd/%.o: os_dbd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${MI} ${PI} -DARGV0=\"ossec-dbd\" -c $^ -o $@

ossec-dbd: ${os_dbd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} ${MI} ${PI} $^  ${OSSEC_LIBS} -o $@


#### os_csyslogd #####

os_csyslogd_c := $(wildcard os_csyslogd/*.c)
os_csyslogd_o := $(os_csyslogd_c:.c=.o)

os_csyslogd/%.o: os_csyslogd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-csyslogd\" -c $^ -o $@

ossec-csyslogd: ${os_csyslogd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### agentlessd ####

os_agentlessd_c := $(wildcard agentlessd/*.c)
os_agentlessd_o := $(os_agentlessd_c:.c=.o)

agentlessd/%.o: agentlessd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-agentlessd\" -c $^ -o $@

ossec-agentlessd: ${os_agentlessd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### os_execd #####

os_execd_c := $(wildcard os_execd/*.c)
os_execd_o := $(os_execd_c:.c=.o)

os_execd/%.o: os_execd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-execd\" -c $^ -o $@

ossec-execd: ${os_execd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### logcollectord ####

os_logcollector_c := $(wildcard logcollector/*.c)
os_logcollector_o := $(os_logcollector_c:.c=.o)
os_logcollector_eventchannel_o := $(os_logcollector_c:.c=-event.o)

logcollector/%.o: logcollector/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-logcollector\" -c $^ -o $@

logcollector/%-event.o: logcollector/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DEVENTCHANNEL_SUPPORT -DARGV0=\"ossec-logcollector\" -c $^ -o $@

ossec-logcollector: ${os_logcollector_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### remoted #########

remoted_c := $(wildcard remoted/*.c)
remoted_o := $(remoted_c:.c=.o)

remoted/%.o: remoted/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./remoted -DARGV0=\"ossec-remoted\" -c $^ -o $@

ossec-remoted: ${remoted_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### ossec-agentd ####

client_agent_c := $(wildcard client-agent/*.c)
client_agent_o := $(client_agent_c:.c=.o)

client-agent/%.o: client-agent/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./client-agent -DARGV0=\"ossec-agentd\" -c $^ -o $@

ossec-agentd: ${client_agent_o} monitord/rotate_log.o monitord/compress_log.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### addagent ######

addagent_c := $(wildcard addagent/*.c)
addagent_o := $(addagent_c:.c=.o)

addagent/%.o: addagent/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./addagent -DARGV0=\"manage_agents\" -c $^ -o $@


manage_agents: ${addagent_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### Util ##########

util_programs = syscheck_update clear_stats agent_control syscheck_control rootcheck_control verify-agent-conf ossec-regex parallel-regex

$(util_programs): $(BUILD_LIBS)

.PHONY: utils
utils: ${util_programs}

util_c := $(wildcard util/*.c)
util_o := $(util_c:.c=.o)

util/%.o: util/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./util -DARGV0=\"utils\" -c $^ -o $@

syscheck_update: util/syscheck_update.o addagent/validate.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

clear_stats: util/clear_stats.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

verify-agent-conf: util/verify-agent-conf.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

agent_control: util/agent_control.o addagent/validate.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

syscheck_control: util/syscheck_control.o addagent/validate.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

rootcheck_control: util/rootcheck_control.o addagent/validate.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

ossec-regex: util/ossec-regex.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

parallel-regex: util/parallel-regex.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### rootcheck #####

rootcheck_c := $(wildcard rootcheck/*.c)
rootcheck_o := $(rootcheck_c:.c=.o)
rootcheck_rk_o := $(rootcheck_c:.c=_rk.o)
rootcheck_o_lib := $(filter-out rootcheck/rootcheck-config.o, ${rootcheck_o})
rootcheck_o_cmd := $(filter-out rootcheck/config.o, ${rootcheck_o})


rootcheck/%.o: rootcheck/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"rootcheck\" -c $^ -o $@

rootcheck/%_rk.o: rootcheck/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"rootcheck\" -UOSSECHIDS -c $^ -o $@


rootcheck.a: ${rootcheck_o_lib}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#ossec-rootcheck: rootcheck/rootcheck-config.o rootcheck.a
#	@echo ${rootcheck_o_cmd}
#	@echo ${rootcheck_o_lib}
#	@echo ${rootcheck_o}
#	${OSSEC_CC} ${OSSEC_CFLAGS} rootcheck/rootcheck-config.o rootcheck.a rootcheck/rootcheck.c  -o $@

#### syscheck ######


syscheck_sql := syscheckd/schema_fim_db.sql
syscheck_c := $(wildcard syscheckd/*.c)
syschecklib_o := $(syschecklib_c:.c=.o) $(syscheck_sql:.sql=.o)
syscheck_o := $(syschecklib_o:.c=.o) $(syscheck_c:.c=.o) $(syscheck_sql:.sql=.o)
syscheck_eventchannel_o := $(syscheck_c:.c=-event.o) $(syscheck_sql:.sql=.o)

syscheckd/schema_fim_db.o: syscheckd/schema_fim_db.sql
	${QUIET_CC}echo 'const char *schema_fim_sql = "'"`cat $< | tr -d \"\n\"`"'";' | ${MING_BASE}${CC} ${OSSEC_CFLAGS} -xc -c -o $@ -

syscheckd/%.o: syscheckd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-syscheckd\" -c $^ -o $@

syscheckd/%-event.o: syscheckd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -DEVENTCHANNEL_SUPPORT -DARGV0=\"ossec-syscheckd\" -c $^ -o $@

ossec-syscheckd: ${syscheck_o} rootcheck.a
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### Monitor #######

monitor_c := $(wildcard monitord/*.c)
monitor_o := $(monitor_c:.c=.o)

monitord/%.o: monitord/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-monitord\" -c $< -o $@

ossec-monitord: ${monitor_o} os_maild/sendcustomemail.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### reportd #######

report_c := reportd/report.c
report_o := $(report_c:.c=.o)

reportd/%.o: reportd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-reportd\" -c $^ -o $@

ossec-reportd: ${report_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


#### os_auth #######

os_auth_c := ${wildcard os_auth/*.c}
os_auth_o := $(os_auth_c:.c=.o)

os_auth/%.o: os_auth/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./os_auth -DARGV0=\"ossec-authd\" -c $^ -o $@

agent-auth: addagent/validate.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

ossec-authd: addagent/validate.o os_auth/main-server.o os_auth/local-server.o os_auth/ssl.o os_auth/check_cert.o os_auth/config.o os_auth/authcom.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### integratord #####

integrator_c := ${wildcard os_integrator/*.c}
integrator_o := $(integrator_c:.c=.o)

os_integrator/%.o: os_integrator/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS}  -I./os_integrator -DARGV0=\"ossec-integratord\" -c $^ -o $@

ossec-integratord: ${integrator_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

#### analysisd #####

cdb_c := ${wildcard analysisd/cdb/*.c}
cdb_o := $(cdb_c:.c=.o)
all_analysisd_o += ${cdb_o}
all_analysisd_libs += cdb.a

analysisd/cdb/%.o: analysisd/cdb/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/cdb -c $^ -o $@

cdb.a: ${cdb_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


alerts_c := ${wildcard analysisd/alerts/*.c}
alerts_o := $(alerts_c:.c=.o)
all_analysisd_o += ${alerts_o}
all_analysisd_libs += alerts.a

analysisd/alerts/%.o: analysisd/alerts/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/alerts -c $^ -o $@

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
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/%-live.o: analysisd/decoders/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/decoders/plugins/%-test.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/plugins/%-live.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/compiled_rules.h: analysisd/compiled_rules/.function_list analysisd/compiled_rules/register_rule.sh
	./analysisd/compiled_rules/register_rule.sh build

analysisd/compiled_rules/%-test.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/%-live.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

decoders-live.a: ${decoders_live_o}
	${OSSEC_LINK} $@ $^

decoders-test.a: ${decoders_test_o}
	${OSSEC_LINK} $@ $^

format_c := ${wildcard analysisd/format/*.c}
format_o := ${format_c:.c=.o}
all_analysisd_o += ${format_o}

analysisd/format/%.o: analysisd/format/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

output_c := ${wildcard analysisd/output/*c}
output_o := ${output_c:.c=.o}
all_analysisd_o += ${output_o}

analysisd/output/%.o: analysisd/output/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@



analysisd_c := ${filter-out analysisd/analysisd.c, ${filter-out analysisd/testrule.c, ${filter-out analysisd/makelists.c, ${wildcard analysisd/*.c}}}}
analysisd_o := ${analysisd_c:.c=.o}
all_analysisd_o += ${analysisd_o}

analysisd_test_o := $(analysisd_o:.o=-test.o)
analysisd_live_o := $(analysisd_o:.o=-live.o)
all_analysisd_o += ${analysisd_test_o} ${analysisd_live_o} analysisd/testrule-test.o analysisd/analysisd-live.o analysisd/analysisd-test.o analysisd/makelists-live.o

analysisd/%-live.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -c $< -o $@

analysisd/%-test.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${OSSEC_CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -c $< -o $@


ossec-logtest: ${analysisd_test_o} ${output_o} ${format_o} analysisd/testrule-test.o analysisd/analysisd-test.o alerts.a cdb.a decoders-test.a
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

ossec-analysisd: ${analysisd_live_o} analysisd/analysisd-live.o ${output_o} ${format_o} alerts.a cdb.a decoders-live.a
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

ossec-makelists: analysisd/makelists-live.o ${filter-out analysisd/state-live.o, ${analysisd_live_o}} ${format_o} alerts.a cdb.a decoders-live.a
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

### wazuh-modulesd ##

wmodulesd_c := wazuh_modules/main.c
wmodulesd_o := $(wmodulesd_c:.c=.o)

wazuh-modulesd: ${wmodulesd_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

### wazuh-framework ##
ifneq (,$(filter ${USE_FRAMEWORK_LIB},YES yes y Y 1))
wazuh-framework: ${shared_o} ${wdblib_o}
	${MAKE} -C ../framework build PREFIX=${PREFIX} USE_FRAMEWORK_LIB=${USE_FRAMEWORK_LIB}
endif

### wazuh-python ###

WPYTHON_DIR := ${PREFIX}/framework/python
OPTIMIZE_CPYTHON?=no

ifneq (,$(filter ${OPTIMIZE_CPYTHON},YES yes y Y 1))
CPYTHON_FLAGS=--enable-optimizations
endif

wpython: install_dependencies install_framework install_mitre

ifeq (${uname_S},Darwin)
WLIBPYTHON=libpython3.8.dylib
else
WLIBPYTHON=libpython3.8.so.1.0
endif

build_python:
ifeq (${uname_S},Darwin)
ifeq (,$(wildcard ${EXTERNAL_CPYTHON}/python.exe))
	export WPATH_LIB="@executable_path/../../../lib"
	export SOURCE_PATH=${ROUTE_PATH}
	export WAZUH_FFI_PATH=${EXTERNAL_LIBFFI}
	export INSTALL_NAME_DIR=${ROUTE_PATH}
	export DYLD_LIBRARY_PATH=${ROUTE_PATH}
	mkdir -p ${ROUTE_PATH}/../lib && cp ${WAZUHEXT_LIB} ${ROUTE_PATH}/../lib
	cd ${EXTERNAL_CPYTHON} && ./configure --prefix="${WPYTHON_DIR}" --enable-shared --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LDFLAGS="-L${ROUTE_PATH} -lwazuhext -Xlinker -rpath -Xlinker @executable_path/../../../lib" CPPFLAGS="-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}" $(CPYTHON_FLAGS) && ${MAKE}
	install_name_tool -change ${WLIBPYTHON} @rpath/../lib/${WLIBPYTHON} external/cpython/${WLIBPYTHON}
	install_name_tool -change ${WPYTHON_DIR}/lib/${WLIBPYTHON} @rpath/../lib/${WLIBPYTHON} -id @rpath/../lib/${WLIBPYTHON} external/cpython/${WLIBPYTHON}
	rm -rf ${ROUTE_PATH}/../lib
endif
else
ifeq (,$(wildcard ${EXTERNAL_CPYTHON}/python))
	export WPATH_LIB="'\$$\$$ORIGIN/../../../lib'" && export SOURCE_PATH=${ROUTE_PATH} && export WAZUH_FFI_PATH=${EXTERNAL_LIBFFI} && export LD_LIBRARY_PATH=${ROUTE_PATH} && cd ${EXTERNAL_CPYTHON} && ./configure --prefix="${WPYTHON_DIR}" --libdir="${WPYTHON_DIR}/lib" --enable-shared --with-openssl="${ROUTE_PATH}/${EXTERNAL_OPENSSL}" LDFLAGS="-L${ROUTE_PATH} -lwazuhext -Wl,-rpath,'\$$\$$ORIGIN/../../../lib',--disable-new-dtags" CPPFLAGS="-I${ROUTE_PATH}/${EXTERNAL_OPENSSL}" $(CPYTHON_FLAGS) && ${MAKE}
endif
endif

ifeq (,$(filter ${DISABLE_SHARED},YES yes y Y 1))
build_python: $(WAZUHEXT_LIB)
endif

install_python:
	cd ${EXTERNAL_CPYTHON} && export WPATH_LIB=${PREFIX}/lib && export SOURCE_PATH=${ROUTE_PATH} && export WAZUH_FFI_PATH=${EXTERNAL_LIBFFI} && ${MAKE} install
	find ${WPYTHON_DIR} -name "*${WLIBPYTHON}" -exec ln -f {} ${PREFIX}/lib/${WLIBPYTHON} \;

python_dependencies := requirements.txt

install_dependencies: install_python
	LD_LIBRARY_PATH="${PREFIX}/lib" LDFLAGS="-L${PREFIX}/lib" ${WPYTHON_DIR}/bin/pip3 install -r ../framework/${python_dependencies}  --index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple

install_framework: install_python
	cd ../framework && ${WPYTHON_DIR}/bin/python3 setup.py install --prefix=${WPYTHON_DIR} --wazuh-version=$(shell cat VERSION) --install-type=${TARGET}
	chown -R root:${OSSEC_GROUP} ${WPYTHON_DIR}
	chmod -R o=- ${WPYTHON_DIR}/*

install_mitre: install_python
	cd ../tools/mitre && ${WPYTHON_DIR}/bin/python3 mitredb.py -d ${PREFIX}/var/db/mitre.db

####################
#### test ##########
####################

CFLAGS_TEST=-g -O0 --coverage -DUNIT_TESTING
LIBS_TEST=-lcmocka

# LIBS_TEST = -lcheck -lm -lrt -lsubunit



unit_tests/wrappers/%.o: unit_tests/wrappers/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/syscheckd/%.o: unit_tests/wrappers/syscheckd/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} ${DEFINES_EVENTCHANNEL} -c $^ -o $@

unit_tests/wrappers/shared/%.o: unit_tests/wrappers/shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

.PHONY: test run_valgrind_tests run_tests build_tests test_valgrind test_coverage

test: build_tests
	${MAKE} run_tests

run_valgrind_tests:
	@$(foreach bin,${test_programs},valgrind --leak-check=full --track-origins=yes --trace-children=no --vgdb=no --gen-suppressions=all --suppressions=tests/valgrind.supp ./${bin} || exit 1;)

run_tests:
	@$(foreach bin,${test_programs},./${bin} || exit 1;)

build_tests: external
	${MAKE} DEBUG=yes TEST=yes ${test_programs}

test_c := $(wildcard tests/*.c)
test_o := $(test_c:.c=.o)

tests/%.o: tests/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

tap_os_crypto: tests/tap_os_crypto.c ${crypto_o} ${shared_o} ${os_xml_o} ${os_net_o} ${os_regex_o}
	${OSSEC_CCBIN} ${OSSEC_CFLAGS} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_os_net: tests/tap_os_net.c ${os_net_o} ${shared_o} ${os_regex_o} ${os_xml_o}
	${OSSEC_CCBIN} ${OSSEC_CFLAGS} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_os_regex: tests/tap_os_regex.c ${os_regex_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_shared: tests/tap_shared.c ${shared_o} ${os_xml_o} ${os_net_o} ${os_regex_o}
	${OSSEC_CCBIN} $(OSSEC_CFLAGS) ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_os_zlib: tests/tap_os_zlib.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_os_xml: tests/tap_os_xml.o ${os_xml_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_fluentd_forwarder: tests/tap_fluentd_forwarder.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

tap_wazuhdb_op: tests/tap_wazuhdb_op.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

test_valgrind: build_tests
	${MAKE} run_valgrind_tests


test_coverage: build_tests
	lcov --base-directory . --directory . --zerocounters --rc lcov_branch_coverage=1 --quiet
	@echo "Running tests\n"

	${MAKE} run_valgrind_tests

	@echo "\nTests finished."

	lcov --base-directory . --directory . --capture --quiet --rc lcov_branch_coverage=1 --output-file ossec.test

	rm -rf coverage-report/
	genhtml --branch-coverage --output-directory coverage-report/ --title "ossec test coverage" --show-details --legend --num-spaces 4 --quiet ossec.test

###################
#### Rule Tests ###
###################

test-rules:
	( cd ../contrib/ossec-testing && sudo python runtests.py)


####################
#### windows #######
####################

win32/icon.o: win32/icofile.rc
	${OSSEC_WINDRES} -i $< -o $@

win32_c := $(wildcard win32/*.c)
win32_o := $(win32_c:.c=.o)

win32/%.o: win32/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -DARGV0=\"ossec-agent\" -c $^ -o $@

win32/%_rk.o: win32/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -UOSSECHIDS -DARGV0=\"ossec-agent\" -c $^ -o $@

win32_ui_c := $(wildcard win32/ui/*.c)
win32_ui_o := $(win32_ui_c:.c=.o)

win32/ui/%.o: win32/ui/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -UOSSECHIDS -DARGV0=\"ossec-win32ui\" -c $^ -o $@

win32/ossec-agent.exe: win32/icon.o win32/win_agent.o win32/win_service.o win32/win_utils.o ${syscheck_o} ${rootcheck_o} $(filter-out wazuh_modules/main.o, ${wmodulesd_o}) $(filter-out client-agent/main.o, $(filter-out client-agent/agentd.o, $(filter-out client-agent/event-forward.o, ${client_agent_o}))) $(filter-out logcollector/main.o, ${os_logcollector_o}) ${os_execd_o} monitord/rotate_log.o monitord/compress_log.o wazuh_modules/syscollector/syscollector_win_ext.dll ${UNIT_TEST_WRAPPERS}
	${OSSEC_CCBIN} -DARGV0=\"ossec-agent\" -DOSSECHIDS ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/ossec-agent-eventchannel.exe: win32/icon.o win32/win_agent.o win32/win_service.o win32/win_utils.o $(filter-out syscheckd/main-event.o, ${syscheck_eventchannel_o}) ${rootcheck_o} $(filter-out wazuh_modules/main.o, ${wmodulesd_o}) $(filter-out client-agent/main.o, $(filter-out client-agent/agentd.o, $(filter-out client-agent/event-forward.o, ${client_agent_o}))) $(filter-out logcollector/main-event.o, ${os_logcollector_eventchannel_o}) ${os_execd_o} monitord/rotate_log.o monitord/compress_log.o wazuh_modules/syscollector/syscollector_win_ext.dll ${UNIT_TEST_WRAPPERS}
	${OSSEC_CCBIN} -DARGV0=\"ossec-agent\" -DOSSECHIDS -DEVENTCHANNEL_SUPPORT ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/ossec-rootcheck.exe: win32/icon.o win32/win_service_rk.o ${rootcheck_rk_o}
	${OSSEC_CCBIN} -DARGV0=\"ossec-rootcheck\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/manage_agents.exe: win32/win_service_rk.o ${addagent_o}
	${OSSEC_CCBIN} -DARGV0=\"manage-agents\" -DMA ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/setup-windows.exe: win32/win_service_rk.o win32/setup-win.o win32/setup-shared.o
	${OSSEC_CCBIN} -DARGV0=\"setup-windows\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/setup-syscheck.exe: win32/setup-syscheck.o win32/setup-shared.o
	${OSSEC_CCBIN} -DARGV0=\"setup-syscheck\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/setup-iis.exe: win32/setup-iis.o
	${OSSEC_CCBIN} -DARGV0=\"setup-iis\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/add-localfile.exe: win32/add-localfile.o
	${OSSEC_CCBIN} -DARGV0=\"add-localfile\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

win32/ui_resource.o: win32/ui/win32ui.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/auth_resource.o: win32/agent-auth.rc
	${OSSEC_WINDRES} -i $< -o $@

win32/os_win32ui.exe: win32/ui_resource.o win32/win_service_rk.o ${win32_ui_o} addagent/b64.o
	${OSSEC_CCBIN} -DARGV0=\"ossec-win32ui\" ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -mwindows -o $@

win32/agent-auth.exe: win32/auth_resource.o win32/win_service_rk.o os_auth/main-client.o os_auth/ssl.o os_auth/main-client.o os_auth/check_cert.o addagent/validate.o
	${OSSEC_CCBIN} -DARGV0=\"agent-auth\" -DOSSECHIDS ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -lshlwapi -lwsock32 -lsecur32 -lws2_32 -flto -o $@

####################
#### Clean #########
####################

clean: clean-test clean-internals clean-external clean-windows clean-framework clean-config

clean-test:
	rm -f ${test_o} ${test_programs} ossec.test
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

ifneq ($(wildcard external/libdb/build_unix/*),)
	cd ${EXTERNAL_LIBDB} && ${MAKE} realclean
endif
endif

clean-wpython:
ifneq ($(wildcard external/cpython/*),)
	-cd ${EXTERNAL_CPYTHON} && ${MAKE} clean && ${MAKE} distclean
endif

clean-deps:
	rm -rf $(EXTERNAL_DIR) $(EXTERNAL_CPYTHON) $(MSU_JSON_GZ)

clean-internals:
	rm -f $(BUILD_SERVER)
	rm -f $(BUILD_AGENT)
	rm -f $(BUILD_LIBS)
	rm -f ${os_zlib_o}
	rm -f ${os_xml_o}
	rm -f ${os_regex_o}
	rm -f ${os_net_o}
	rm -f ${shared_o}
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
	rm -f ${util_o} ${util_programs}
	rm -f ${rootcheck_o} ${rootcheck_rk_o} rootcheck.a
	rm -f ${syscheck_o} ${syscheck_eventchannel_o}
	rm -f ${monitor_o}
	rm -f ${os_auth_o}
	rm -f ${all_analysisd_o} ${all_analysisd_libs} analysisd/compiled_rules/compiled_rules.h
	rm -f ${integrator_o}
	rm -f ${wmodulesd_o} ${wmodules_o}
	rm -f ${wdb_o}
	rm -f ${SELINUX_MODULE}
	rm -f ${SELINUX_POLICY}
	rm -f ${wrappers_syscheck_o}
	rm -f ${wrappers_shared_o}

clean-framework:
	${MAKE} -C ../framework clean

clean-windows:
	rm -f libwazuh.a
	rm -f libwazuhext.dll
	rm -f wazuh_modules/syscollector/*.o
	rm -f wazuh_modules/syscollector/syscollector_win_ext.dll
	rm -f win32/LICENSE.txt
	rm -f win32/help_win.txt
	rm -f win32/internal_options.conf
	rm -f win32/default-local_internal_options.conf
	rm -f win32/default-ossec.conf
	rm -f win32/default-ossec-pre6.conf
	rm -f win32/restart-ossec.cmd
	rm -f win32/route-null.cmd
	rm -f win32/route-null-2012.cmd
	rm -f win32/netsh.cmd
	rm -f win32/netsh-win-2016.cmd
	rm -f ${win32_o} ${win32_ui_o} win32/win_service_rk.o
	rm -f win32/icon.o win32/resource.o
	rm -f ${WINDOWS_BINS}
	rm -f win32/wazuh-agent-*.exe
	rm -f win32/libwinpthread-1.dll
	rm -f win32/VERSION
	rm -f win32/REVISION

clean-config:
	rm -f ../etc/ossec.mc
	rm -f Config.OS
