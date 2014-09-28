

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')





EXTERNAL_JSON=external/cJSON/
EXTERNAL_LUA=external/lua/
EXTERNAL_ZLIB=external/zlib-1.2.8/
LUA_PLAT=posix
MAX=2048
DEFINES=-DMAX_AGENTS=${MAX} -DOSSECHIDS

ifeq (${uname_S},Linux)
		DEFINES+=-DUSEINOTIFY
#		DEFINES+=-DUSE_MAGIC
		TEXTRA=-lpthread
#		LIB_MAGIC=-lmagic
else
ifeq (${uname_S},AIX)
		DEFINES+=-DAIX
		DEFINES+=-DHIGHFIRST
		PATH=${PATH}:/usr/vac/bin

else
ifeq (${uname_S},SunOS)
		DEFINES+=-DSOLARIS
		DEFINES+=-DHIGHFIRST
		IEXTRA=-lsocket -lnsl -lresolv
		LUA_PLAT=solaris

else
ifeq (${uname_S},Darwin)
		DEFINES+=-DDarwin
		DEFINES+=-DHIGHFIRST
		LUA_PLAT=macosx

else
ifeq (${uname_S},FreeBSD)
		DEFINES+=-DFreeBSD
		TEXTRA=-pthread
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
	QUIET_CC = @printf '    %b %b\n' ${CCCOLOR}CC${ENDCOLOR} ${SRCCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_LINK = @printf '    %b %b\n' ${LINKCOLOR}LINK${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_CCBIN = @printf '    %b %b\n' ${LINKCOLOR}CC${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_INSTALL = @printf '    %b %b\n' ${LINKCOLOR}INSTALL${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_RANLIB = @printf '    %b %b\n' ${LINKCOLOR}RANLIB${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
endif

OSSEC_CC=${QUIET_CC}${CC}
OSSEC_CCBIN=${QUIET_CCBIN}${CC}
OSSEC_LINK=${QUIET_LINK}${BUILDLIB}
OSSEC_RANLIB=${QUIET_RANLIB}ranlib

####################
#### External ######
####################

ifndef TARGET
	TARGET=server
endif # TARGET

.PHONY: default 
default: ${TARGET}

server: deps \
	ossec-maild \
	ossec-csyslogd \
	ossec-agentlessd \
	ossec-execd \
	ossec-logcollector \
	ossec-remoted \
	ossec-agentd \
	manage_agents \
	util \
	ossec-syscheckd \
	ossec-monitord \
	ossec-reportd \
	os_auth \
	ossec-analysisd \
	ossec-logtest \
	ossec-makelists

agent: deps \
	ossec-agentd \
	agent-auth \
	ossec-logcollector \
	ossec-syscheckd \
	ossec-execd \
	manage_agents \
	

.PHONY: win
win:
	${MAKE} -f Makefile.mingw


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
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"shared-libs\" -c $^ -o $@

shared.a: ${shared_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### Config ##########

config_c = $(wildcard config/*.c)
config_o = $(config_c:.c=.o)

config/%.o: config/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"config-libs\" -c $^ -o $@

config.a: ${config_o}
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

#### crypto ##########

crypto_blowfish_c = os_crypto/blowfish/bf_op.c \
										os_crypto/blowfish/bf_skey.c \
										os_crypto/blowfish/bf_enc.c
crypto_blowfish_o = $(crypto_blowfish_c:.c=.o)

os_crypto/blowfish/%.o: os_crypto/blowfish/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"crypto\" -c $^ -o $@

crypto_md5_c = os_crypto/md5/md5.c \
							 os_crypto/md5/md5_op.c
crypto_md5_o = $(crypto_md5_c:.c=.o)

os_crypto/md5/%.o: os_crypto/md5/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"crypto\" -c $^ -o $@

crypto_sha1_c = os_crypto/sha1/sha1_op.c
crypto_sha1_o = $(crypto_sha1_c:.c=.o)

os_crypto/sha1/%.o: os_crypto/sha1/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"crypto\" -c $^ -o $@

crypto_md5_sha1_c = os_crypto/md5_sha1/md5_sha1_op.c
crypto_md5_sha1_o = $(crypto_md5_sha1_c:.c=.o)

os_crypto/md5_sha1/%.o: os_crypto/md5_sha1/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"crypto\" -c $^ -o $@

crypto_shared_c = $(wildcard os_crypto/shared/*.c)
crypto_shared_o = $(crypto_shared_c:.c=.o)

os_crypto/shared/%.o: os_crypto/shared/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"crypto\" -c $^ -o $@


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
	${OSSEC_CCBIN} ${CFLAGS} ${IEXTRA} $^ -o $@

#### os_dbd ##########

#### os_csyslogd #####

os_csyslogd_c = $(wildcard os_csyslogd/*.c)
os_csyslogd_o = $(os_csyslogd_c:.c=.o)

os_csyslogd/%.o: os_csyslogd/%.c
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} -DARGV0=\"ossec-csyslogd\" -c $^ -o $@

ossec-csyslogd: ${os_csyslogd_o} ${ossec_libs} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${JSON_INCLUDE} ${IEXTRA} $^ -lm -o $@


#### agentlessd ####

os_agentlessd_c = $(wildcard agentlessd/*.c)
os_agentlessd_o = $(os_agentlessd_c:.c=.o)

agentlessd/%.o: agentlessd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-agentlessd\" -c $^ -o $@

ossec-agentlessd: ${os_agentlessd_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} ${IEXTRA} $^ -o $@

#### os_execd #####

os_execd_c = $(wildcard os_execd/*.c)
os_execd_o = $(os_execd_c:.c=.o)

os_execd/%.o: os_execd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-execd\" -c $^ -o $@

ossec-execd: ${os_execd_o} ${ossec_libs} ${JSON_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${JSON_INCLUDE} ${IEXTRA} $^ -lm -o $@


#### logcollectord ####

os_logcollector_c = $(wildcard logcollector/*.c)
os_logcollector_o = $(os_logcollector_c:.c=.o)

logcollector/%.o: logcollector/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-logcollector\" -c $^ -o $@

ossec-logcollector: ${os_logcollector_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} ${IEXTRA} $^ -o $@

#### remoted #########

remoted_c = $(wildcard remoted/*.c)
remoted_o = $(remoted_c:.c=.o)

remoted/%.o: remoted/%.c
	${OSSEC_CC} ${CFLAGS} -I./remoted ${ZLIB_INCLUDE} -DARGV0=\"ossec-remoted\" -c $^ -o $@

ossec-remoted: ${remoted_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ ${TEXTRA} -o $@

#### ossec-agentd ####

client_agent_c = $(wildcard ./client-agent/*.c)
client_agent_o = $(client_agent_c:.c=.o)

client-agent/%.o: client-agent/%.c
	${OSSEC_CC} ${CFLAGS} -I./client-agent ${ZLIB_INCLUDE} -DARGV0=\"ossec-agentd\" -c $^ -o $@

ossec-agentd: ${client_agent_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ ${TEXTRA} -lpthread -o $@

#### addagent ######

addagent_c = $(wildcard addagent/*.c)
addagent_o = $(addagent_c:.c=.o)

addagent/%.o: addagent/%.c
	${OSSEC_CC} ${CFLAGS} -I./addagent ${ZLIB_INCLUDE} -DARGV0=\"manage_agents\" -c $^ -o $@


manage_agents: ${addagent_o} ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

#### Util ##########

util_programs = syscheck_update clear_stats list_agents agent_control syscheck_control rootcheck_control verify-agent-conf ossec-regex

util: ${util_programs}

util_c = $(wildcard util/*.c)
util_o = $(util_c:.c=.o)

util/%.o: util/%.c
	${OSSEC_CC} ${CFLAGS} -I./util ${ZLIB_INCLUDE} -DARGV0=\"utils\" -c $^ -o $@

syscheck_update: util/syscheck_update.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

clear_stats: util/clear_stats.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

list_agents: util/list_agents.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

verify-agent-conf: util/verify-agent-conf.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

agent_control: util/agent_control.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

syscheck_control: util/syscheck_control.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

rootcheck_control: util/rootcheck_control.o addagent/validate.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

ossec-regex: util/ossec-regex.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@

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
#	${OSSEC_CC} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} rootcheck/rootcheck-config.o rootcheck.a rootcheck/rootcheck.c ${ZLIB_LIB} ${ossec_libs}  -o $@

#### syscheck ######


syscheck_c = $(wildcard syscheckd/*.c)
syscheck_o = $(syscheck_c:.c=.o)

syscheckd/%.o: syscheckd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"syscheckd\" -c $^ -o $@

ossec-syscheckd: ${syscheck_o} rootcheck.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ ${LIB_MAGIC} -o $@

#### Monitor #######

monitor_c = $(wildcard monitord/*.c)
monitor_o = $(monitor_c:.c=.o)

monitord/%.o: monitord/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"monitord\" -c $^ -o $@

ossec-monitord: ${monitor_o} ${ossec_libs} os_maild/sendcustomemail.o ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} ${ZLIB_INCLUDE} ${IEXTRA} $^ -o $@


#### reportd #######

report_c = reportd/report.c
report_o = $(report_c:.c=.o)

reportd/%.o: reportd/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"reportd\" -c $^ -o $@

ossec-reportd: ${report_o} ${ossec_libs}
	${OSSEC_CCBIN} ${CFLAGS} $^ -o $@


#### os_auth #######


os_auth_programs = agent-auth ossec-authd

os_auth: ${os_auth_programs}

os_auth_c = ${wildcard os_auth/*.c}
os_auth_o = $(os_auth_c:.c=.o)

os_auth/%.o: os_auth/%.c
	${OSSEC_CC} ${CFLAGS} -DUSE_OPENSSL -I./os_auth -DARGV0=\"auth\" -c $^ -o $@

agent-auth: addagent/validate.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DUSE_OPENSSL -I./os_auth $^ ${OPENSSLCMD} -lssl -lcrypto -o $@

ossec-authd: addagent/validate.o os_auth/main-server.o os_auth/ssl.o os_auth/check_cert.o ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DUSE_OPENSSL -I./os_auth $^ ${OPENSSLCMD} -lssl -lcrypto -o $@

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
	${OSSEC_CCBIN} ${CFLAGS} -DTESTRULE -DUSE_OPENSSL $^ -o $@

ossec-analysisd: ${analysisd_live_o} analysisd/analysisd-live.o ${output_o} alerts.a cdb.a decoders-live.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} -DUSE_OPENSSL $^ -o $@

ossec-makelists: analysisd/makelists-live.o ${analysisd_live_o} ${output_a} alerts.a cdb.a decoders-test.a ${ossec_libs} ${ZLIB_LIB}
	${OSSEC_CCBIN} ${CFLAGS} $^ -o $@



####################
#### test ##########
####################

test: all
		cd tests/ && ${MAKE}

check: test

####################
#### Clean #########
####################

clean: clean-test clean-interals clean-external

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






