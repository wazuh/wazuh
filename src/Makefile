
# II: mysql and postgresql

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')






EXTERNAL_JSON=external/cJSON/
EXTERNAL_LUA=external/lua/
EXTERNAL_ZLIB=external/zlib-1.2.8/
LUA_PLAT=posix
MAXAGENTS?=2048
# XXX Becareful NO EXTRA Spaces here
PREFIX?=/var/ossec
PG_CONFIG?=pg_config
MY_CONFIG?=mysql_config
PRELUDE_CONFIG?=libprelude-config
OSSEC_GROUP?=ossec
OSSEC_USER?=ossec
OSSEC_USER_MAIL?=ossecm
OSSEC_USER_REM?=ossecr

USE_PRELUDE?=no
USE_ZEROMQ?=no
USE_PICVIZ?=yes
USE_GEOIP?=no
USE_OPENSSL?=auto

ONEWAY?=no
CLEANFULL?=no

DEFINES=-DMAX_AGENTS=${MAXAGENTS} -DOSSECHIDS
DEFINES+=-DDEFAULTDIR=\"${PREFIX}\"
DEFINES+=-DUSER=\"${OSSEC_USER}\"
DEFINES+=-DREMUSER=\"${OSSEC_USER_REM}\"
DEFINES+=-DGROUPGLOBAL=\"${OSSEC_GROUP}\"
DEFINES+=-DMAILUSER=\"${OSSEC_USER_MAIL}\"


LDFLAGS+=-lm

ifeq (${uname_S},Linux)
		DEFINES+=-DINOTIFY_ENABLED
#		DEFINES+=-DUSE_MAGIC
		LDFLAGS+=-lpthread
#		LDFLAGS+=-lmagic
else
ifeq (${uname_S},AIX)
		DEFINES+=-DAIX
		DEFINES+=-DHIGHFIRST
		PATH=${PATH}:/usr/vac/bin
else
ifeq (${uname_S},SunOS)
		DEFINES+=-DSOLARIS
		DEFINES+=-DHIGHFIRST
		LDFLAGS+=-lsocket -lnsl -lresolv
		LUA_PLAT=solaris
		PATH=${PATH}:/usr/ccs/bin:/usr/xpg4/bin:/opt/csw/gcc3/bin:/opt/csw/bin:/usr/sfw/bin

else
ifeq (${uname_S},Darwin)
		DEFINES+=-DDarwin
		DEFINES+=-DHIGHFIRST
		LUA_PLAT=macosx

else
ifeq (${uname_S},FreeBSD)
		DEFINES+=-DFreeBSD
		LDFLAGS+=-pthread
		LUA_PLAT=freebsd
else
ifeq (${uname_S},OpenBSD)
#		DEFINES+=-DOpenBSD
		DEFINES+=-pthread
		LUA_PLAT=posix
		CFLAGS+=-I/usr/local/include
		LDFLAGS+=-L/usr/local/lib
else
ifeq (${uname_S},HP-UX)
		DEFINES+=-DHPUX
		DEFINES+=-D_XOPEN_SOURCE_EXTENDED
		DEFINES+=-DHIGHFIRST
		DEFINES+=-D_REENTRANT
else
	    # Unknow platform
endif # HPUX
endif # OpenBSD
endif # FreeBSD
endif # Darwin
endif # SunOS
endif # AIX
endif # Linux

ifdef DEBUGAD
	DEFINES+=+DDEBUGAD
endif

ifdef DEBUG
	CFLAGS+=-g
else
	CFLAGS+=-O2
endif #DEBUG

ifneq (,$(filter ${CLEANFULL},yes y Y 1))
	DEFINES+=-DCLEANFULL
endif

ifneq (,$(filter ${ONEWAY},yes y Y 1))
	DEFINES+=-DONEWAY_ENABLED
endif

CFLAGS+=${DEFINES}
CFLAGS+=-Wall -Wextra -Werror
CFLAGS+=-I./ -I./headers/


CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[37;1m"
MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifndef V
	QUIET_CC      = @printf '    %b %b\n' ${CCCOLOR}CC${ENDCOLOR} ${SRCCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_LINK    = @printf '    %b %b\n' ${LINKCOLOR}LINK${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_CCBIN   = @printf '    %b %b\n' ${LINKCOLOR}CC${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_INSTALL = @printf '    %b %b\n' ${LINKCOLOR}INSTALL${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_RANLIB  = @printf '    %b %b\n' ${LINKCOLOR}RANLIB${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_NOTICE  = @printf '%b' ${MAKECOLOR} 1>&2;
	QUIET_ENDCOLOR= @printf '%b' ${ENDCOLOR} 1>&2;
endif

OSSEC_CC     =${QUIET_CC}${CC}
OSSEC_CCBIN  =${QUIET_CCBIN}${CC}
OSSEC_LINK   =${QUIET_LINK}ar -rc
OSSEC_RANLIB =${QUIET_RANLIB}ranlib


ifneq (,$(filter ${USE_PRELUDE},auto yes y Y 1))
	DEFINES+=-DPRELUDE_OUTPUT_ENABLED
	LDFLAGS+=-lprelude
	LDFLAGS+=$(shell sh -c '${PRELUDE_CONFIG} --pthread-cflags')
	LDFLAGS+=$(shell sh -c '${PRELUDE_CONFIG} --libs')
endif # USE_PRELUDE

ifneq (,$(filter ${USE_ZEROMQ},auto yes y Y 1))
	DEFINES+=-DZEROMQ_OUTPUT_ENABLED
	#LDFLAGS+=-L/usr/local/lib -I/usr/local/include -lzmq -lczmq
	LDFLAGS+=-lzmq -lczmq -lm
endif # USE_ZEROMQ

ifneq (,$(filter ${USE_PICVIZ},auto yes y Y 1))
	DEFINES+=-DPICVIZ_OUTPUT_ENABLED
endif # USE_PICVIZ

ifneq (,$(filter ${USE_GEOIP},auto yes y Y 1))
	DEFINES+=-DLIBGEOIP_ENABLED
	LDFLAGS+=-lGeoIP
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

			ifeq (${MI},) # BEGIN MI manula detection
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
					ML="-L/usr/lib/mysql -lmysqlclient"
				else
					ifneq (,$(wildcard /usr/lib64/mysql/*))
						ML="-L/usr/lib64/mysql -lmysqlclient"
					else
						ifneq (,$(wildcard /usr/local/lib/mysql/*))
							ML="-L/usr/local/lib/mysql -lmysqlclient"
						else
							ifneq (,$(wildcard /usr/local/lib64/mysql/*))
								ML="-L/usr/local/lib64/mysql -lmysqlclient"
							endif # local/lib64
						endif # local/lib
					endif # lib54
				endif # lib
			endif
		endif # MYSQL_LIBS

		LDFLAGS+=${ML}

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

			LDFLAGS+=${PL}
			LDFLAGS+=-lpq

		endif # pgsql
	endif # mysql
endif # DATABASE


# openssl ###########

ifeq (${USE_OPENSSL},auto)
	ifneq (,$(wildcard /usr/include/openssl/ssl.h))
		DEFINES+=-DLIBOPENSSL_ENABLED
		LDFLAGS+=-lssl -lcrypto
	else
		ifneq (,$(wildcard /usr/local/include/openssl/ssl.h))
			DEFINES+=-DLIBOPENSSL_ENABLED
			LDFLAGS+=-lssl -lcrypto
		endif
	endif
endif

ifneq (,$(filter ${USE_PRELUDE},yes y Y 1))
	DEFINES+=-DLIBOPENSSL_ENABLED
	ifneq (${OPENSSL_LIBS},)
		LDFLAGS+=-lssl
		LDFLAGS+=-lcrypto
	else
		LDFLAGS+=${OPENSSL_LIBS}
	endif 

	ifneq (${OPENSSL_CFLAGS},)
		CFLAGS+=${OPENSSL_CFLAGS}
	endif
endif

####################
#### Target ########
####################

OSSEC_CONTROL_SRC=./init/ossec-server.sh
OSSEC_CONF_SRC=../etc/ossec-server.conf

ifndef TARGET
	TARGET=failtarget
endif # TARGET

ifeq (${TARGET},agent)
	DEFINES+=-DCLIENT
	OSSEC_CONTROL_SRC=./init/ossec-client.sh
	OSSEC_CONF_SRC=../etc/ossec-agent.conf
endif

ifeq (${TARGET},local)
	DEFINES+=-DLOCAL
	OSSEC_CONTROL_SRC=./init/ossec-local.sh
	OSSEC_CONF_SRC=../etc/ossec-local.conf
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


.PHONY: install install-agent install-server install-local install-hybrid
install: install-${TARGET}

install-agent: install-common
	install -m 0550 -o root -g 0 ossec-agentd ${PREFIX}/bin
	install -m 0550 -o root -g 0 agent-auth ${PREFIX}/bin

	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/rids

	install -d -m 0770 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/tmp

install-local: install-server-generic

install-hybrid: install-server-generic

install-server: install-server-generic

install-common: build
	./init/adduser.sh ${OSSEC_USER} ${OSSEC_USER_MAIL} ${OSSEC_USER_REM} ${OSSEC_GROUP} ${PREFIX}
	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/logs
	install -m 0660 -o ${OSSEC_USER} -g ${OSSEC_GROUP} /dev/null ${PREFIX}/logs/ossec.log

	install -d -m 0550 -o root -g 0 ${PREFIX}/bin
	install -d -m 0550 -o root -g 0 ${PREFIX}/lua
	install -d -m 0550 -o root -g 0 ${PREFIX}/lua/native
	install -d -m 0550 -o root -g 0 ${PREFIX}/lua/compiled
	install -m 0550 -o root -g 0 ossec-logcollector ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-syscheckd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-execd ${PREFIX}/bin
	install -m 0550 -o root -g 0 manage_agents ${PREFIX}/bin
	install -m 0550 -o root -g 0 external/lua/src/ossec-lua ${PREFIX}/bin/
	install -m 0550 -o root -g 0 external/lua/src/ossec-luac ${PREFIX}/bin/
	install -m 0550 -o root -g 0 ../contrib/util.sh ${PREFIX}/bin/
	install -m 0550 -o root -g 0 ${OSSEC_CONTROL_SRC} ${PREFIX}/bin/ossec-control

	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/queue
	install -d -m 0770 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/alerts
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/ossec
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/syscheck
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/diff

	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/etc
	install -m 0440 -o root -g ${OSSEC_GROUP} /etc/localtime ${PREFIX}/etc
ifneq (,$(wildcard /etc/TIMEZONE))
	install -m 440 -o root -g ${OSSEC_GROUP} /etc/TIMEZONE ${PREFIX}/etc/
endif
# Solaris Needs some extra files
ifeq (${uname_S},SunOS)
	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/usr/share/lib/zoneinfo/
	install -m 0440 -o root -g ${OSSEC_GROUP} /usr/share/lib/zoneinfo/* ${PREFIX}/usr/share/lib/zoneinfo/
endif
	install -m 0640 -o root -g ${OSSEC_GROUP} -b ../etc/internal_options.conf ${PREFIX}/etc/
ifeq (,$(wildcard ${PREFIX}/etc/local_internal_options.conf))
	install -m 0640 -o root -g ${OSSEC_GROUP} ../etc/local_internal_options.conf ${PREFIX}/etc/local_internal_options.conf
endif
ifeq (,$(wildcard ${PREFIX}/etc/client.keys))
	install -m 0640 -o root -g ${OSSEC_GROUP} /dev/null ${PREFIX}/etc/client.keys
endif
ifeq (,$(wildcard ${PREFIX}/etc/ossec.conf))
ifneq (,$(wildcard ../etc/ossec.mc))
	install -m 0640 -o root -g ${OSSEC_GROUP} ../etc/ossec.mc ${PREFIX}/etc/ossec.conf
else
	install -m 0640 -o root -g ${OSSEC_GROUP} ${OSSEC_CONF_SRC} ${PREFIX}/etc/ossec.conf
endif
endif

	install -d -m 0770 -o root -g ${OSSEC_GROUP} ${PREFIX}/etc/shared
	install -m 0440 -o root -g ${OSSEC_GROUP} rootcheck/db/*.txt ${PREFIX}/etc/shared/

	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/active-response
	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/active-response/bin
	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/agentless
	install -m 0550 -o root -g ${OSSEC_GROUP} agentlessd/scripts/* ${PREFIX}/agentless/

	install -d -m 0700 -o root -g ${OSSEC_GROUP} ${PREFIX}/.ssh

	install -m 0550 -o root -g ${OSSEC_GROUP} ../active-response/*.sh ${PREFIX}/active-response/bin/
	install -m 0550 -o root -g ${OSSEC_GROUP} ../active-response/firewalls/*.sh ${PREFIX}/active-response/bin/

	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/var
	install -d -m 0770 -o root -g ${OSSEC_GROUP} ${PREFIX}/var/run

	./init/fw-check.sh execute



install-server-generic: install-common
	install -m 0660 -o ${OSSEC_USER} -g ${OSSEC_GROUP} /dev/null ${PREFIX}/logs/active-responses.log
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/logs/archives
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/logs/alerts
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/logs/firewall

	install -m 0550 -o root -g 0 ossec-agentlessd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-analysisd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-monitord ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-reportd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-maild ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-remoted ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-logtest ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-csyslogd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-authd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-dbd ${PREFIX}/bin
	install -m 0550 -o root -g 0 ossec-makelists ${PREFIX}/bin
	install -m 0550 -o root -g 0 verify-agent-conf ${PREFIX}/bin/
	install -m 0550 -o root -g 0 clear_stats ${PREFIX}/bin/
	install -m 0550 -o root -g 0 list_agents ${PREFIX}/bin/
	install -m 0550 -o root -g 0 ossec-regex ${PREFIX}/bin/
	install -m 0550 -o root -g 0 syscheck_update ${PREFIX}/bin/
	install -m 0550 -o root -g 0 agent_control ${PREFIX}/bin/
	install -m 0550 -o root -g 0 syscheck_control ${PREFIX}/bin/
	install -m 0550 -o root -g 0 rootcheck_control ${PREFIX}/bin/

	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/stats
	install -d -m 0550 -o root -g ${OSSEC_GROUP} ${PREFIX}/rules
ifneq (,$(wildcard ${PREFIX}/rules/local_rules.xml))
	cp ${PREFIX}/rules/local_rules.xml ${PREFIX}/rules/local_rules.xml.installbackup
	install -m 0640 -o root -g ${OSSEC_GROUP} -b ../etc/rules/*.xml ${PREFIX}/rules
	install -m 0640 -o root -g ${OSSEC_GROUP} ${PREFIX}/rules/local_rules.xml.installbackup ${PREFIX}/rules/local_rules.xml
	rm ${PREFIX}/rules/local_rules.xml.installbackup
else
	install -m 0640 -o root -g ${OSSEC_GROUP} -b ../etc/rules/*.xml ${PREFIX}/rules
endif

	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/fts

	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/rootcheck

	install -d -m 0750 -o ${OSSEC_USER_REM} -g ${OSSEC_GROUP} ${PREFIX}/queue/agent-info
	install -d -m 0750 -o ${OSSEC_USER} -g ${OSSEC_GROUP} ${PREFIX}/queue/agentless

	install -d -m 0750 -o ${OSSEC_USER_REM} -g ${OSSEC_GROUP} ${PREFIX}/queue/rids

	install -d -m 0750 -o root -g ${OSSEC_GROUP} ${PREFIX}/tmp

	install -m 0640 -o root -g ${OSSEC_GROUP} ../etc/decoder.xml ${PREFIX}/etc/
	install -m 0640 -o root -g ${OSSEC_GROUP} /dev/null ${PREFIX}/etc/local_decoder.xml

	rm -f ${PREFIX}/etc/shared/merged.mg


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
	@echo "   make V=1              Display full compiler messages"
	@echo "   make DEBUG=1          Build with symbols and without optimization"
	@echo "   make PREFIX=/path     Install OSSEC to '/path'. Defaults to /var/ossec"
	@echo "   make MAXAGENTS=NUMBER Set the number of maximum agents to NUMBER. Defaults to 2048"
	@echo
	@echo "Database options: "
	@echo "   make DATABASE=mysql  Build with MYSQL Support"
	@echo "                        Use MYSQL_CFLAGS adn MYSQL_LIBS to override defaults"
	@echo "   make DATABASE=pgsql  Build with PostgreSQL Support "
	@echo "                        Use PGSQL_CFLAGS adn PGSQL_LIBS to override defaults"
	@echo
	@echo "Geoip support: "
	@echo "   make USE_GEOIP=1     Build with GeoIP support"
	@echo
	@echo
	@echo "Examples: Client with debugging enabled"
	@echo "   make TARGET=agent DEBUG=1"

.PHONY: settings
settings:
	@echo
	@echo "General settings:"
	@echo "    TARGET:           ${TARGET}"
	@echo "    V:                ${V}"
	@echo "    DEBUG:            ${DEBUG}"
	@echo "    DEBUGAD           ${DEBUGAD}"
	@echo "    PREFIX:           ${PREFIX}"
	@echo "    MAXAGENTS:        ${MAXAGENTS}"
	@echo "    DATABASE:         ${DATABASE}"
	@echo "    ONEWAY:           ${ONEWAY}"
	@echo "    CLEANFULL:        ${CLEANFULL}"
	@echo "User settings:"
	@echo "    OSSEC_GROUP:      ${OSSEC_GROUP}"
	@echo "    OSSEC_USER:       ${OSSEC_USER}"
	@echo "    OSSEC_USER_MAIL:  ${OSSEC_USER_MAIL}"
	@echo "    OSSEC_USER_REM:   ${OSSEC_USER_REM}"
	@echo "Lua settings:"
	@echo "    LUA_PLAT:         ${LUA_PLAT}"
	@echo "USE settings:"
	@echo "    USE_ZEROMQ:       ${USE_ZEROMQ}"
	@echo "    USE_GEOIP:        ${USE_GEOIP}"
	@echo "    USE_PRELUDE:      ${USE_PRELUDE}"
	@echo "    USE_OPENSSL:      ${USE_OPENSSL}"
	@echo "    USE_PICVIZ:       ${USE_PICVIZ}"
	@echo "Mysql settings:"
	@echo "    includes:         ${MI}"
	@echo "    libs:             ${ML}"
	@echo "Pgsql settings:"
	@echo "    includes:         ${PI}"
	@echo "    libs:             ${PL}"
	@echo "Defines:"
	@echo "    ${DEFINES}"
	@echo "Compiler:"
	@echo "    CFLAGS            ${CFLAGS}"
	@echo "    LDFLAGS           ${LDFLAGS}"
	@echo "    CC                ${CC}"
	@echo "    MAKE              ${MAKE}"


BUILD_SERVER+=external
BUILD_SERVER+=ossec-maild
BUILD_SERVER+=ossec-csyslogd
BUILD_SERVER+=ossec-agentlessd
BUILD_SERVER+=ossec-execd
BUILD_SERVER+=ossec-logcollector
BUILD_SERVER+=ossec-remoted
BUILD_SERVER+=ossec-agentd
BUILD_SERVER+=manage_agents
BUILD_SERVER+=utils
BUILD_SERVER+=ossec-syscheckd
BUILD_SERVER+=ossec-monitord
BUILD_SERVER+=ossec-reportd
ifneq (,$(filter ${USE_OPENSSL},auto yes))
BUILD_SERVER+=ossec-authd
endif
BUILD_SERVER+=ossec-analysisd
BUILD_SERVER+=ossec-logtest
BUILD_SERVER+=ossec-makelists
BUILD_SERVER+=ossec-dbd

BUILD_AGENT+=external
BUILD_AGENT+=ossec-agentd
ifneq (,$(filter ${USE_OPENSSL},auto yes))
BUILD_AGENT+=agent-auth
endif
BUILD_AGENT+=ossec-logcollector
BUILD_AGENT+=ossec-syscheckd
BUILD_AGENT+=ossec-execd
BUILD_AGENT+=manage_agents

.PHONY: server local hybrid agent
server: ${BUILD_SERVER}

local: ${BUILD_SERVER}

hybrid: ${BUILD_SERVER}

agent: ${BUILD_AGENT}


.PHONY: winagent
winagent:
	# enable old working windows build for travis
	#${MAKE} -f Makefile.mingw
	( cd win32 && /bin/sh ./gen_win.sh )
	( cd win-pkg && /bin/sh ./make.sh )


####################
#### External ######
####################

.PHONY: external lua
external: libcJSON.a ${EXTERNAL_ZLIB}libz.a lua

lua:
	cd ${EXTERNAL_LUA} && ${MAKE} ${LUA_PLAT}

${EXTERNAL_ZLIB}libz.a:
	cd ${EXTERNAL_ZLIB} && ./configure && ${MAKE} libz.a


#### zlib ##########

ZLIB_LIB=os_zlib.a ${EXTERNAL_ZLIB}libz.a
ZLIB_INCLUDE=-I./${EXTERNAL_ZLIB}

os_zlib_c := os_zlib/os_zlib.c
os_zlib_o := $(os_zlib_c:.c=.o)

os_zlib/%.o: os_zlib/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_zlib.a: ${os_zlib_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@



#### cJSON #########

JSON_LIB=libcJSON.a
JSON_INCLUDE=-I./${EXTERNAL_JSON}

cjson_c := ${EXTERNAL_JSON}cJSON.c
cjson_o := $(cjson_c:.c=.o)

${EXTERNAL_JSON}%.o: ${EXTERNAL_JSON}%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

libcJSON.a: ${cjson_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@



####################
#### OSSEC Libs ####
####################

ossec_libs = os_crypto.a config.a shared.a os_net.a os_regex.a os_xml.a

#### os_xml ########

os_xml_c := $(wildcard os_xml/*.c)
os_xml_o := $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_xml.a: ${os_xml_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


#### os_regex ######

os_regex_c := $(wildcard os_regex/*.c)
os_regex_o := $(os_regex_c:.c=.o)

os_regex/%.o: os_regex/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_regex.a: ${os_regex_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### os_net ##########

os_net_c := $(wildcard os_net/*.c)
os_net_o := $(os_net_c:.c=.o)

os_net/%.o: os_net/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_net.a: ${os_net_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### Shared ##########

shared_c := $(wildcard shared/*.c)
shared_o := $(shared_c:.c=.o)

shared/%.o: shared/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

shared.a: ${shared_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### Config ##########

config_c := $(wildcard config/*.c)
config_o := $(config_c:.c=.o)

config/%.o: config/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

config.a: ${config_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### crypto ##########

crypto_blowfish_c := os_crypto/blowfish/bf_op.c \
										os_crypto/blowfish/bf_skey.c \
										os_crypto/blowfish/bf_enc.c
crypto_blowfish_o := $(crypto_blowfish_c:.c=.o)

os_crypto/blowfish/%.o: os_crypto/blowfish/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_md5_c := os_crypto/md5/md5.c \
							 os_crypto/md5/md5_op.c
crypto_md5_o := $(crypto_md5_c:.c=.o)

os_crypto/md5/%.o: os_crypto/md5/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_sha1_c := os_crypto/sha1/sha1_op.c
crypto_sha1_o := $(crypto_sha1_c:.c=.o)

os_crypto/sha1/%.o: os_crypto/sha1/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_md5_sha1_c := os_crypto/md5_sha1/md5_sha1_op.c
crypto_md5_sha1_o := $(crypto_md5_sha1_c:.c=.o)

os_crypto/md5_sha1/%.o: os_crypto/md5_sha1/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_shared_c := $(wildcard os_crypto/shared/*.c)
crypto_shared_o := $(crypto_shared_c:.c=.o)

os_crypto/shared/%.o: os_crypto/shared/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@


crypto_o := ${crypto_blowfish_o} \
					 ${crypto_md5_o} \
					 ${crypto_sha1_o} \
					 ${crypto_shared_o} \
					 ${crypto_md5_sha1_o}

os_crypto.a: ${crypto_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


#### os_mail #########

os_maild_c := $(wildcard os_maild/*.c)
os_maild_o := $(os_maild_c:.c=.o)

os_maild/%.o: os_maild/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-maild\" -c $^ -o $@

ossec-maild: ${os_maild_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

#### os_dbd ##########

os_dbd_c := $(wildcard os_dbd/*.c)
os_dbd_o := $(os_dbd_c:.c=.o)

os_dbd/%.o: os_dbd/%.c
	${OSSEC_CC} ${CFLAGS} ${MI} ${PI} -DARGV0=\"ossec-dbd\" -c $^ -o $@

ossec-dbd: ${os_dbd_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} ${MI} ${PI} ${JSON_INCLUDE} $^ -lm ${LDFLAGS} -o $@


#### os_csyslogd #####

os_csyslogd_c := $(wildcard os_csyslogd/*.c)
os_csyslogd_o := $(os_csyslogd_c:.c=.o)

os_csyslogd/%.o: os_csyslogd/%.c
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} -DARGV0=\"ossec-csyslogd\" -c $^ -o $@

ossec-csyslogd: ${os_csyslogd_o} ${ossec_libs} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${JSON_INCLUDE} $^ -lm ${LDFLAGS} -o $@


#### agentlessd ####

os_agentlessd_c := $(wildcard agentlessd/*.c)
os_agentlessd_o := $(os_agentlessd_c:.c=.o)

agentlessd/%.o: agentlessd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-agentlessd\" -c $^ -o $@

ossec-agentlessd: ${os_agentlessd_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

#### os_execd #####

os_execd_c := $(wildcard os_execd/*.c)
os_execd_o := $(os_execd_c:.c=.o)

os_execd/%.o: os_execd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-execd\" -c $^ -o $@

ossec-execd: ${os_execd_o} ${ossec_libs} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${JSON_INCLUDE} $^ -lm ${LDFLAGS} -o $@


#### logcollectord ####

os_logcollector_c := $(wildcard logcollector/*.c)
os_logcollector_o := $(os_logcollector_c:.c=.o)

logcollector/%.o: logcollector/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-logcollector\" -c $^ -o $@

ossec-logcollector: ${os_logcollector_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

#### remoted #########

remoted_c := $(wildcard remoted/*.c)
remoted_o := $(remoted_c:.c=.o)

remoted/%.o: remoted/%.c
	${OSSEC_CC} ${CFLAGS} -I./remoted ${ZLIB_INCLUDE} -DARGV0=\"ossec-remoted\" -c $^ -o $@

ossec-remoted: ${remoted_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### ossec-agentd ####

client_agent_c := $(wildcard ./client-agent/*.c)
client_agent_o := $(client_agent_c:.c=.o)

client-agent/%.o: client-agent/%.c
	${OSSEC_CC} ${CFLAGS} -I./client-agent ${ZLIB_INCLUDE} -DARGV0=\"ossec-agentd\" -c $^ -o $@

ossec-agentd: ${client_agent_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### addagent ######

addagent_c := $(wildcard addagent/*.c)
addagent_o := $(addagent_c:.c=.o)

addagent/%.o: addagent/%.c
	${OSSEC_CC} ${CFLAGS} -I./addagent ${ZLIB_INCLUDE} -DARGV0=\"manage_agents\" -c $^ -o $@


manage_agents: ${addagent_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### Util ##########

util_programs = syscheck_update clear_stats list_agents agent_control syscheck_control rootcheck_control verify-agent-conf ossec-regex

.PHONY: utils
utils: ${util_programs}

util_c := $(wildcard util/*.c)
util_o := $(util_c:.c=.o)

util/%.o: util/%.c
	${OSSEC_CC} ${CFLAGS} -I./util ${ZLIB_INCLUDE} -DARGV0=\"utils\" -c $^ -o $@

syscheck_update: util/syscheck_update.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

clear_stats: util/clear_stats.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

list_agents: util/list_agents.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

verify-agent-conf: util/verify-agent-conf.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

agent_control: util/agent_control.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

syscheck_control: util/syscheck_control.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

rootcheck_control: util/rootcheck_control.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

ossec-regex: util/ossec-regex.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### rootcheck #####

rootcheck_c := $(wildcard rootcheck/*.c)
rootcheck_o := $(rootcheck_c:.c=.o)
rootcheck_o_lib := $(filter-out rootcheck/rootcheck-config.o, ${rootcheck_o})
rootcheck_o_cmd := $(filter-out rootcheck/config.o, ${rootcheck_o})


rootcheck/%.o: rootcheck/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"rootcheck\" -c $^ -o $@


rootcheck.a: ${rootcheck_o_lib}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#ossec-rootcheck: rootcheck/rootcheck-config.o rootcheck.a ${ossec_libs}
#	@echo ${rootcheck_o_cmd}
#	@echo ${rootcheck_o_lib}
#	@echo ${rootcheck_o}
#	${OSSEC_CC} ${CFLAGS} ${ZLIB_INCLUDE} rootcheck/rootcheck-config.o rootcheck.a rootcheck/rootcheck.c ${ZLIB_LIB} ${ossec_libs}  -o $@

#### syscheck ######


syscheck_c := $(wildcard syscheckd/*.c)
syscheck_o := $(syscheck_c:.c=.o)

syscheckd/%.o: syscheckd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-syscheckd\" -c $^ -o $@

ossec-syscheckd: ${syscheck_o} rootcheck.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### Monitor #######

monitor_c := $(wildcard monitord/*.c)
monitor_o := $(monitor_c:.c=.o)

monitord/%.o: monitord/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-monitord\" -c $^ -o $@

ossec-monitord: ${monitor_o} ${ossec_libs} os_maild/sendcustomemail.o ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@


#### reportd #######

report_c := reportd/report.c
report_o := $(report_c:.c=.o)

reportd/%.o: reportd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-reportd\" -c $^ -o $@

ossec-reportd: ${report_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@


#### os_auth #######

os_auth_c := ${wildcard os_auth/*.c}
os_auth_o := $(os_auth_c:.c=.o)

os_auth/%.o: os_auth/%.c
	${OSSEC_CC} ${CFLAGS}  -I./os_auth -DARGV0=\"auth\" -c $^ -o $@

agent-auth: addagent/validate.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -I./os_auth $^ ${LDFLAGS} -o $@

ossec-authd: addagent/validate.o os_auth/main-server.o os_auth/ssl.o os_auth/check_cert.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -I./os_auth $^ ${LDFLAGS} -o $@

#### analysisd #####

cdb_c := ${wildcard analysisd/cdb/*.c}
cdb_o := $(cdb_c:.c=.o)
all_analysisd_o += ${cdb_o}
all_analysisd_libs += cdb.a

analysisd/cdb/%.o: analysisd/cdb/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/cdb -c $^ -o $@

cdb.a: ${cdb_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


alerts_c := ${wildcard analysisd/alerts/*.c}
alerts_o := $(alerts_c:.c=.o)
all_analysisd_o += ${alerts_o}
all_analysisd_libs += alerts.a

analysisd/alerts/%.o: analysisd/alerts/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/alerts -c $^ -o $@

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
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/%-live.o: analysisd/decoders/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/decoders/plugins/%-test.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/plugins/%-live.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/compiled_rules.h: analysisd/compiled_rules/.function_list analysisd/compiled_rules/register_rule.sh
	./analysisd/compiled_rules/register_rule.sh build

analysisd/compiled_rules/%-test.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/%-live.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

decoders-live.a: ${decoders_live_o}
	${OSSEC_LINK} $@ $^

decoders-test.a: ${decoders_test_o}
	${OSSEC_LINK} $@ $^

format_c := ${wildcard analysisd/format/*.c}
format_o := ${format_c:.c=.o} 
all_analysisd_o += ${format_o}

analysisd/format/%.o: analysisd/format/%.c
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@

output_c := ${wildcard analysisd/output/*c}
output_o := ${output_c:.c=.o}
all_analysisd_o += ${output_o}

analysisd/output/%.o: analysisd/output/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -I./analysisd/decoders -c $^ -o $@



analysisd_c := ${filter-out analysisd/analysisd.c, ${filter-out analysisd/testrule.c, ${filter-out analysisd/makelists.c, ${wildcard analysisd/*.c}}}}
analysisd_o := ${analysisd_c:.c=.o}
all_analysisd_o += ${analysisd_o}

analysisd_test_o := $(analysisd_o:.o=-test.o)
analysisd_live_o := $(analysisd_o:.o=-live.o)
all_analysisd_o += ${analysisd_test_o} ${analysisd_live_o} analysisd/testrule-test.o analysisd/analysisd-live.o analysisd/analysisd-test.o analysisd/makelists-live.o

analysisd/%-live.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-analysisd\" -I./analysisd -c $< -o $@

analysisd/%-test.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"ossec-analysisd\" -I./analysisd -c $< -o $@


ossec-logtest: ${analysisd_test_o} ${output_o} ${format_o} analysisd/testrule-test.o analysisd/analysisd-test.o alerts.a cdb.a decoders-test.a ${ossec_libs} ${ZLIB_LIB} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DTESTRULE $^ ${LDFLAGS} -o $@

ossec-analysisd: ${analysisd_live_o} analysisd/analysisd-live.o ${output_o} ${format_o} alerts.a cdb.a decoders-live.a ${ossec_libs} ${ZLIB_LIB} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@
	#${OSSEC_CCBIN} ${CFLAGS} -L../external -I../external/cJSON -L./external -lcJSON -I./external/cJSON $^ ${LDFLAGS} -o $@

ossec-makelists: analysisd/makelists-live.o ${analysisd_live_o} ${output_o} ${format_o} alerts.a cdb.a decoders-test.a ${ossec_libs} ${ZLIB_LIB} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@



####################
#### test ##########
####################

CFLAGS_TEST = -g -O0 --coverage

LDFLAGS_TEST = -lcheck -lm -pthread -lrt

ifdef TEST
	CFLAGS+=${CFLAGS_TEST}
	LDFLAGS+=${LDFLAGS_TEST}
endif #TEST

test_programs = test_os_zlib test_os_xml test_os_regex test_os_crypto test_os_net test_shared

.PHONY: test run_tests build_tests test_valgrind test_coverage

test: build_tests
	${MAKE} run_tests

run_tests:
	@$(foreach bin,${test_programs},./${bin};)	
	
build_tests: external
	${MAKE} DEBUG=1 TEST=1 ${test_programs}

test_c := $(wildcard tests/*.c)
test_o := $(test_c:.c=.o)

tests/%.o: tests/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@
	
test_os_zlib: tests/test_os_zlib.o ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

test_os_xml: tests/test_os_xml.o ${os_xml_o}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

test_os_regex: tests/test_os_regex.c ${os_regex_o}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

test_os_crypto: tests/test_os_crypto.c ${crypto_o} ${shared_o} ${os_xml_o} ${os_net_o} ${os_regex_o} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

test_os_net: tests/test_os_net.c ${os_net_o} ${shared_o} ${os_regex_o} ${os_xml_o}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

test_shared: tests/test_shared.c ${shared_o} ${os_xml_o} ${os_net_o} ${os_regex_o}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

test_valgrind: build_tests
	valgrind --leak-check=full --track-origins=yes --trace-children=yes --vgdb=no --error-exitcode=1 --gen-suppressions=all --suppressions=tests/valgrind.supp ${MAKE} run_tests


test_coverage: build_tests
	lcov --base-directory . --directory . --zerocounters --rc lcov_branch_coverage=1 --quiet
	@echo "Running tests\n"

	${MAKE} run_tests

	@echo "\nTests finished."
	
	lcov --base-directory . --directory . --capture --quiet --rc lcov_branch_coverage=1 --output-file ossec.test
	
	rm -rf coverage-report/
	genhtml --branch-coverage --output-directory coverage-report/ --title "ossec test coverage" --show-details --legend --num-spaces 4 --quiet ossec.test

####################
#### RUule Tests ###
####################

test-rules: 
	( cd ../contrib/ossec-testing && sudo python runtests.py) 

####################
#### Clean #########
####################

clean: clean-test clean-internals clean-external clean-windows-old

clean-test:
	rm -f ${test_o} ${test_programs} ossec.test
	rm -Rf coverage-report/
	find . -name "*.gcno" -exec rm {} \;
	find . -name "*.gcda" -exec rm {} \;

clean-external:
	rm -f ${cjson_o} libcJSON.a
	cd ${EXTERNAL_ZLIB} && ${MAKE} -f Makefile.in distclean
	cd ${EXTERNAL_LUA} && ${MAKE} clean


clean-internals:
	rm -f ${os_zlib_o} os_zlib.a
	rm -f ${os_xml_o} os_xml.a
	rm -f ${os_regex_o} os_regex.a
	rm -f ${os_net_o} os_net.a
	rm -f ${shared_o} shared.a
	rm -f ${config_o} config.a
	rm -f ${os_maild_o} ossec-maild
	rm -f ${crypto_o} os_crypto.a
	rm -f ${os_csyslogd_o} ossec-csyslogd
	rm -f ${os_dbd_o} ossec-dbd
	rm -f ${os_agentlessd_o} ossec-agentlessd
	rm -f ${os_execd_o} ossec-execd
	rm -f ${os_logcollector_o} ossec-logcollector
	rm -f ${remoted_o} ossec-remoted
	rm -f ${report_o} ossec-reportd
	rm -f ${client_agent_o} ossec-agentd
	rm -f ${addagent_o} manage_agents
	rm -f ${util_o} ${util_programs}
	rm -f ${rootcheck_o} rootcheck.a
	rm -f ${syscheck_o} ossec-syscheckd
	rm -f ${monitor_o} ossec-monitord
	rm -f ${os_auth_o} ossec-authd agent-auth
	rm -f ${all_analysisd_o} ${all_analysisd_libs} analysisd/compiled_rules/compiled_rules.h
	rm -f ossec-logtest ossec-analysisd ossec-makelists

clean-windows-old:
	rm -rf win-pkg/
	rm -f win32/LICENSE.txt
	rm -f win32/help_win.txt
	rm -f win32/internal_options-win.conf
	rm -f win32/local_internal_options-win.conf
	rm -f win32/ossec-win.conf
	rm -f win32/restart-ossec.cmd
	rm -f win32/route-null.cmd
