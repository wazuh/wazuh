

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')






EXTERNAL_JSON=external/cJSON/
EXTERNAL_LUA=external/lua/
EXTERNAL_ZLIB=external/zlib-1.2.8/
LUA_PLAT=posix
MAXAGENTS?=2048
# XXX Becareful NO EXTRA Spaces here 
PREFIX?=/var/ossec
export PREFIX 
PG_CONFIG?=pg_config 
MY_CONFIG?=mysql_config 

USE_ZEROMQ?=0
USE_GEOIP?=0

DEFINES=-DMAX_AGENTS=${MAXAGENTS} -DOSSECHIDS

ifeq (${uname_S},Linux)
		DEFINES+=-DUSEINOTIFY
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
ifeq (${uname_S},HP-UX)
		DEFINES+=-DHPUX
		DEFINES+=-D_XOPEN_SOURCE_EXTENDED
		DEFINES+=-DHIGHFIRST
		DEFINES+=-D_REENTRANT
else
	    # Unknow platform
endif # HPUX
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
endif #DEBUG

CFLAGS+=${DEFINES} 
CFLAGS+=-Wall -Wextra -O2
CFLAGS+=-I./ -I./headers/


BUILDLIB=ar -crus


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

OSSEC_CC=${QUIET_CC}${CC}
OSSEC_CCBIN=${QUIET_CCBIN}${CC}
OSSEC_LINK=${QUIET_LINK}${BUILDLIB}
OSSEC_RANLIB=${QUIET_RANLIB}ranlib

####################
#### Target ########
####################

ifndef TARGET
	TARGET=failtarget
endif # TARGET

ifeq (${TARGET},agent)
	DEFINES+=-DCLIENT 
endif


ifeq (${USE_GEOIP},1)
	DEFINES+=-DGEOIP
	LDFLAGS+=-lGeoIP
endif # USE_GEOIP

ifdef DATABASE 

ifeq (${DATABASE},mysql)

DEFINES+=-DUMYSQL

ifdef MYSQL_CFLAGS 
	MI = ${MYSQL_CFLAGS} 
else 
	MI := $(shell sh -c '${MY_CONFIG} --include 2>/dev/null || echo ')

ifeq (${MI},) # BEGIN MI manula detection
ifeq (,$(wildcard /usr/include/mysql/mysql.h))
	MI="-I/usr/include/mysql/"
else 
ifeq (,$(wildcard /usr/local/include/mysql/mysql.h)) 
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
ifeq (,$(wildcard /usr/lib/mysql/*))
	ML="-L/usr/lib/mysql -lmysqlclient"
else 
ifeq (,$(wildcard /usr/lib64/mysql/*))
	ML="-L/usr/lib64/mysql -lmysqlclient"
else 
ifeq (,$(wildcard /usr/local/lib/mysql/*))
	ML="-L/usr/local/lib/mysql -lmysqlclient"
else 
ifeq (,$(wildcard /usr/local/lib64/mysql/*))
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

DEFINES+=-DUPOSTGRES

ifneq (${PGSQL_LIBS},)
	PL:=${PGSQL_LIBS} 
else 
	PL:=$(shell sh -c '(${PG_CONFIG} --libdir --pkglibdir 2>/dev/null | sed "s/^/-L/g" | xargs ) || echo ')
endif 

ifneq (${PGSQL_CFLAGS},)
	PI:=${PGSQL_CFLAGS}
else
	PI:=$(shell sh -c '(${PG_CONFIG}--includedir --pkgincludedir 2>/dev/null | sed "s/^/-I/g" | xargs ) || echo ')
endif 

# XXX need some basic autodetech stuff here.  

LDFLAGS+=${PL}
LDFLAGS+=-lpq

endif # pgsql 
endif # mysql 
endif # DATABASE

.PHONY: default 
build:: ${TARGET}
	@echo 
	${QUIET_NOTICE}
	@echo "Done building ${TARGET}"
	${QUIET_ENDCOLOR}
	@echo 


.PHONY: install 
install: install-${TARGET}

install-agent: build 
	@./InstallAgent.sh

install-server: build 
	@./InstallServer.sh 



.PHONY: failtarget
failtarget: 
	@echo "TARGET is required: "
	@echo "   make TARGET=server   to build the server"
	@echo "   make TARGET=agent    to build the unix agent"
	@echo "   make TARGET=winagent to build the windows agent"

.PHONY: help 
help: failtarget 
	@echo 
	@echo "General options: "
	@echo "   make V=1             Display full compiler messages" 
	@echo "   make DEBUG=1         Build with symbols and without optimization"
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
	@echo "    TARGET:     ${TARGET}"
	@echo "    V:          ${V}"
	@echo "    DEBUG:      ${DEBUG}"
	@echo "    DEBUGAD     ${DEBUGAD}"
	@echo "    PREFIX:     ${PREFIX}"
	@echo "    MAXAGENTS:  ${MAXAGENTS}"
	@echo "    DATABASE:   ${DATABASE}"
	@echo "Lua settings:"
	@echo "    LUA_PLAT:   ${LUA_PLAT}"
	@echo "USE settings:"
	@echo "    USE_ZEROMQ: ${USE_ZEROMQ}"
	@echo "    USE_GEOIP:  ${USE_GEOIP}"
	@echo "Mysql settings:"
	@echo "    includes:   ${MI}"
	@echo "    libs:       ${ML}"
	@echo "Pgsql settings:"
	@echo "    includes:   ${PI}"
	@echo "    libs:       ${PL}"
	@echo "Defines:"
	@echo "    ${DEFINES}"
	@echo "Compiler:"
	@echo "    CFLAGS      ${CFLAGS}" 
	@echo "    LDFLAGS     ${LDFLAGS}"
	@echo "    CC          ${CC}"
	@echo "    MAKE        ${MAKE}"


BUILD_SERVER+=deps 
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
BUILD_SERVER+=ossec-authd
BUILD_SERVER+=ossec-analysisd
BUILD_SERVER+=ossec-logtest
BUILD_SERVER+=ossec-makelists
BUILD_SERVER+=ossec-dbd
	
BUILD_AGENT+=deps
BUILD_AGENT+=ossec-agentd
BUILD_AGENT+=agent-auth
BUILD_AGENT+=ossec-logcollector
BUILD_AGENT+=ossec-syscheckd
BUILD_AGENT+=ossec-execd
BUILD_AGENT+=manage_agents

server: ${BUILD_SERVER}
	@echo ${BUILD_SERVER}

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

deps: libcJSON.a ${EXTERNAL_ZLIB}libz.a
	cd ${EXTERNAL_LUA} && ${MAKE} ${LUA_PLAT}

${EXTERNAL_ZLIB}libz.a:
	cd ${EXTERNAL_ZLIB} && ./configure && ${MAKE} libz.a


#### zlib ##########

ZLIB_LIB=os_zlib.a ${EXTERNAL_ZLIB}libz.a
ZLIB_INCLUDE=-I./${EXTERNAL_ZLIB}

os_zlib_c = os_zlib/os_zlib.c
os_zlib_o = $(os_zlib_c:.c=.o)

os_zlib/%.o: os_zlib/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_zlib.a: ${os_zlib_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@



#### cJSON #########

JSON_LIB=libcJSON.a
JSON_INCLUDE=-I./${EXTERNAL_JSON}

cjson_c= ${EXTERNAL_JSON}cJSON.c
cjson_o = $(cjson_c:.c=.o)

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

os_xml_c= $(wildcard os_xml/*.c)
os_xml_o = $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_xml.a: ${os_xml_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


#### os_regex ######

os_regex_c= $(wildcard os_regex/*.c)
os_regex_o = $(os_regex_c:.c=.o)

os_regex/%.o: os_regex/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_regex.a: ${os_regex_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### os_net ##########

os_net_c = $(wildcard os_net/*.c)
os_net_o = $(os_net_c:.c=.o)

os_net/%.o: os_net/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_net.a: ${os_net_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### Shared ##########

shared_c = $(wildcard shared/*.c)
shared_o = $(shared_c:.c=.o)

shared/%.o: shared/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

shared.a: ${shared_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### Config ##########

config_c = $(wildcard config/*.c)
config_o = $(config_c:.c=.o)

config/%.o: config/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

config.a: ${config_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### crypto ##########

crypto_blowfish_c = os_crypto/blowfish/bf_op.c \
										os_crypto/blowfish/bf_skey.c \
										os_crypto/blowfish/bf_enc.c
crypto_blowfish_o = $(crypto_blowfish_c:.c=.o)

os_crypto/blowfish/%.o: os_crypto/blowfish/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_md5_c = os_crypto/md5/md5.c \
							 os_crypto/md5/md5_op.c
crypto_md5_o = $(crypto_md5_c:.c=.o)

os_crypto/md5/%.o: os_crypto/md5/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_sha1_c = os_crypto/sha1/sha1_op.c
crypto_sha1_o = $(crypto_sha1_c:.c=.o)

os_crypto/sha1/%.o: os_crypto/sha1/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_md5_sha1_c = os_crypto/md5_sha1/md5_sha1_op.c
crypto_md5_sha1_o = $(crypto_md5_sha1_c:.c=.o)

os_crypto/md5_sha1/%.o: os_crypto/md5_sha1/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

crypto_shared_c = $(wildcard os_crypto/shared/*.c)
crypto_shared_o = $(crypto_shared_c:.c=.o)

os_crypto/shared/%.o: os_crypto/shared/%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@


crypto_o = ${crypto_blowfish_o} \
					 ${crypto_md5_o} \
					 ${crypto_sha1_o} \
					 ${crypto_shared_o} \
					 ${crypto_md5_sha1_o}

os_crypto.a: ${crypto_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


#### os_mail #########

os_maild_c = $(wildcard os_maild/*.c)
os_maild_o = $(os_maild_c:.c=.o)

os_maild/%.o: os_maild/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-maild\" -c $^ -o $@

ossec-maild: ${os_maild_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

#### os_dbd ##########

os_dbd_c = $(wildcard os_dbd/*.c)
os_dbd_o = $(os_dbd_c:.c=.o)

os_dbd/%.o: os_dbd/%.c
	${OSSEC_CC} ${CFLAGS} ${MI} ${PI} -DARGV0=\"ossec-dbd\" -c $^ -o $@

ossec-dbd: ${os_dbd_o} ${ossec_libs} 
	${OSSEC_CCBIN} ${CFLAGS} ${MI} ${PI} ${JSON_INCLUDE} $^ -lm ${LDFLAGS} -o $@


#### os_csyslogd #####

os_csyslogd_c = $(wildcard os_csyslogd/*.c)
os_csyslogd_o = $(os_csyslogd_c:.c=.o)

os_csyslogd/%.o: os_csyslogd/%.c
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} -DARGV0=\"ossec-csyslogd\" -c $^ -o $@

ossec-csyslogd: ${os_csyslogd_o} ${ossec_libs} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${JSON_INCLUDE} $^ -lm ${LDFLAGS} -o $@


#### agentlessd ####

os_agentlessd_c = $(wildcard agentlessd/*.c)
os_agentlessd_o = $(os_agentlessd_c:.c=.o)

agentlessd/%.o: agentlessd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-agentlessd\" -c $^ -o $@

ossec-agentlessd: ${os_agentlessd_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

#### os_execd #####

os_execd_c = $(wildcard os_execd/*.c)
os_execd_o = $(os_execd_c:.c=.o)

os_execd/%.o: os_execd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-execd\" -c $^ -o $@

ossec-execd: ${os_execd_o} ${ossec_libs} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${JSON_INCLUDE} $^ -lm ${LDFLAGS} -o $@


#### logcollectord ####

os_logcollector_c = $(wildcard logcollector/*.c)
os_logcollector_o = $(os_logcollector_c:.c=.o)

logcollector/%.o: logcollector/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-logcollector\" -c $^ -o $@

ossec-logcollector: ${os_logcollector_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@

#### remoted #########

remoted_c = $(wildcard remoted/*.c)
remoted_o = $(remoted_c:.c=.o)

remoted/%.o: remoted/%.c
	${OSSEC_CC} ${CFLAGS} -I./remoted ${ZLIB_INCLUDE} -DARGV0=\"ossec-remoted\" -c $^ -o $@

ossec-remoted: ${remoted_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### ossec-agentd ####

client_agent_c = $(wildcard ./client-agent/*.c)
client_agent_o = $(client_agent_c:.c=.o)

client-agent/%.o: client-agent/%.c
	${OSSEC_CC} ${CFLAGS} -I./client-agent ${ZLIB_INCLUDE} -DARGV0=\"ossec-agentd\" -c $^ -o $@

ossec-agentd: ${client_agent_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### addagent ######

addagent_c = $(wildcard addagent/*.c)
addagent_o = $(addagent_c:.c=.o)

addagent/%.o: addagent/%.c
	${OSSEC_CC} ${CFLAGS} -I./addagent ${ZLIB_INCLUDE} -DARGV0=\"manage_agents\" -c $^ -o $@


manage_agents: ${addagent_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### Util ##########

util_programs = syscheck_update clear_stats list_agents agent_control syscheck_control rootcheck_control verify-agent-conf ossec-regex

utils: ${util_programs}

util_c = $(wildcard util/*.c)
util_o = $(util_c:.c=.o)

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

rootcheck_c = $(wildcard rootcheck/*.c)
rootcheck_o = $(rootcheck_c:.c=.o)
rootcheck_o_lib = $(filter-out rootcheck/rootcheck-config.o, ${rootcheck_o})
rootcheck_o_cmd = $(filter-out rootcheck/config.o, ${rootcheck_o})


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


syscheck_c = $(wildcard syscheckd/*.c)
syscheck_o = $(syscheck_c:.c=.o)

syscheckd/%.o: syscheckd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"syscheckd\" -c $^ -o $@

ossec-syscheckd: ${syscheck_o} rootcheck.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@

#### Monitor #######

monitor_c = $(wildcard monitord/*.c)
monitor_o = $(monitor_c:.c=.o)

monitord/%.o: monitord/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"monitord\" -c $^ -o $@

ossec-monitord: ${monitor_o} ${ossec_libs} os_maild/sendcustomemail.o ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} $^ ${LDFLAGS} -o $@


#### reportd #######

report_c = reportd/report.c
report_o = $(report_c:.c=.o)

reportd/%.o: reportd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"reportd\" -c $^ -o $@

ossec-reportd: ${report_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@


#### os_auth #######

os_auth_c = ${wildcard os_auth/*.c}
os_auth_o = $(os_auth_c:.c=.o)

os_auth/%.o: os_auth/%.c
	${OSSEC_CC} ${CFLAGS} -DUSE_OPENSSL -I./os_auth -DARGV0=\"auth\" -c $^ -o $@

agent-auth: addagent/validate.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DUSE_OPENSSL -I./os_auth $^ ${OPENSSLCMD} -lssl -lcrypto ${LDFLAGS} -o $@

ossec-authd: addagent/validate.o os_auth/main-server.o os_auth/ssl.o os_auth/check_cert.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DUSE_OPENSSL -I./os_auth $^ ${OPENSSLCMD} -lssl -lcrypto ${LDFLAGS} -o $@

#### analysisd #####

cdb_c = ${wildcard analysisd/cdb/*.c}
cdb_o = $(cdb_c:.c=.o)
all_analysisd_o += ${cdb_o}
all_analysisd_libs += cdb.a

analysisd/cdb/%.o: analysisd/cdb/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/cdb -c $^ -o $@

cdb.a: ${cdb_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@


alerts_c = ${wildcard analysisd/alerts/*.c}
alerts_o = $(alerts_c:.c=.o)
all_analysisd_o += ${alerts_o}
all_analysisd_libs += alerts.a

analysisd/alerts/%.o: analysisd/alerts/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/alerts -c $^ -o $@

alerts.a: ${alerts_o}
	${OSSEC_LINK} $@ $^

decoders_c = ${wildcard analysisd/decoders/*.c} ${wildcard analysisd/decoders/plugins/*.c} ${wildcard analysisd/compiled_rules/*.c}
decoders_o = $(decoders_c:.c=.o)
## XXX Nasty hack
decoders_test_o = $(decoders_c:.c=-test.o)
decoders_live_o = $(decoders_c:.c=-live.o)

all_analysisd_o += ${decoders_o} ${decoders_test_o} ${decoders_live_o}
all_analysisd_libs += decoders.a decoders-test.a decoders-live.a


analysisd/decoders/%-test.o: analysisd/decoders/%.c
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/%-live.o: analysisd/decoders/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@

analysisd/decoders/plugins/%-test.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@


analysisd/decoders/plugins/%-live.o: analysisd/decoders/plugins/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@
	
analysisd/compiled_rules/compiled_rules.h: analysisd/compiled_rules/.function_list analysisd/compiled_rules/register_rule.sh
	./analysisd/compiled_rules/register_rule.sh build

analysisd/compiled_rules/%-test.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@

analysisd/compiled_rules/%-live.o: analysisd/compiled_rules/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@

decoders-live.a: ${decoders_live_o}
	${OSSEC_LINK} $@ $^

decoders-test.a: ${decoders_test_o}
	${OSSEC_LINK} $@ $^


output_c = ${wildcard analysisd/output/*c}
output_o = ${output_c:.c=.o}
all_analysisd_o += ${output_o}

analysisd/output/%.o: analysisd/output/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -I./analysisd/decoders -c $^ -o $@



analysisd_c = ${filter-out analysisd/analysisd.c, ${filter-out analysisd/testrule.c, ${filter-out analysisd/makelists.c, ${wildcard analysisd/*.c}}}}
analysisd_o = ${analysisd_c:.c=.o}
all_analysisd_o += ${analysisd_o}

analysisd_test_o = $(analysisd_o:.o=-test.o)
analysisd_live_o = $(analysisd_o:.o=-live.o)
all_analysisd_o += ${analysisd_test_o} ${analysisd_live_o} analysisd/testrule-test.o analysisd/analysisd-live.o analysisd/analysisd-test.o analysisd/makelists-live.o

analysisd/%-live.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -c $< -o $@

analysisd/%-test.o: analysisd/%.c analysisd/compiled_rules/compiled_rules.h
	${OSSEC_CC} ${CFLAGS} -DTESTRULE -DARGV0=\"analysisd\" -I./analysisd -DUSE_OPENSSL -c $< -o $@


ossec-logtest: ${analysisd_test_o} ${output_o} analysisd/testrule-test.o analysisd/analysisd-test.o alerts.a cdb.a decoders-test.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DTESTRULE -DUSE_OPENSSL $^ ${LDFLAGS} -o $@

ossec-analysisd: ${analysisd_live_o} analysisd/analysisd-live.o ${output_o} alerts.a cdb.a decoders-live.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DUSE_OPENSSL $^ ${LDFLAGS} -o $@

ossec-makelists: analysisd/makelists-live.o ${analysisd_live_o} ${output_a} alerts.a cdb.a decoders-test.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} $^ ${LDFLAGS} -o $@



####################
#### test ##########
####################

test: deps
		cd tests/ && ${MAKE}

check: test

####################
#### Clean #########
####################

clean: clean-test clean-interals clean-external clean-windows-old

clean-test:
		cd tests/ && ${MAKE} clean

clean-external:
	rm -f ${cjson_o} libcJSON.a
	cd ${EXTERNAL_ZLIB} && ${MAKE} -f Makefile.in distclean
	cd ${EXTERNAL_LUA} && ${MAKE} clean


clean-interals:
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
	rm -f ${os_auth_o} ${os_auth_programs}
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
