

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_S := $(shell sh -c ' 2>/dev/null || echo not')





EXTERNAL_JSON=external/cJSON/
EXTERNAL_LUA=external/lua/
LUA_PLAT=posix
MAX=2048
DEFINES=-DMAX_AGENTS=${MAX} -DOSSECHIDS

ifeq ($(uname_S),Linux)
		DEFINES+=-DUSEINOTIFY
		DEFINES+=-DUSE_MAGIC
		TEXTRA=-lpthread
		LIB_MAGIC=-lmagic
else 
ifeq ($(uname_S),AIX)
		DEFINES+=-DAIX
		DEFINES+=-DHIGHFIRST
		PATH=${PATH}:/usr/vac/bin

else 
ifeq ($(uname_S),SunOS)
		DEFINES+=-DSOLARIS
		DEFINES+=-DHIGHFIRST
		IEXTRA=-lsocket -lnsl -lresolv
		LUA_PLAT=solaris

else 
ifeq ($(uname_S),Darwin)
		DEFINES+=-DDarwin
		DEFINES+=-DHIGHFIRST
		LUA_PLAT=macosx

else 
ifeq ($(uname_S),FreeBSD)
		DEFINES+=-DFreeBSD
		TEXTRA=-pthread
		LUA_PLAT=freebsd
else 
ifeq ($(uname_S),HP-UX)
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


CFLAGS+=${DEFINES}
CFLAGS+=-g -Wall -I./ -I./headers  
#CFLAGS+=-pedantic
BUILDLIB=ar -crus


CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[37;1m"
MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifndef V
	QUIET_CC = @printf '    %b %b\n' $(CCCOLOR)CC$(ENDCOLOR) $(SRCCOLOR)$@$(ENDCOLOR) 1>&2;
	QUIET_LINK = @printf '    %b %b\n' $(LINKCOLOR)LINK$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
	QUIET_INSTALL = @printf '    %b %b\n' $(LINKCOLOR)INSTALL$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
endif

OSSEC_CC=${QUIET_CC}${CC}
OSSEC_LINK=${QUIET_LINK}${BUILDLIB}

all:  deps \
			ossec-maild \
			ossec-csyslogd \
			ossec-agentlessd \
			ossec-execd \
			ossec-logcollector \
			ossec-remoted 


####################
#### External ###### 
####################

deps: libcJSON.a
	cd external && make zlib
	cd ${EXTERNAL_LUA} && make ${LUA_PLAT} 


#### cJSON #########

JSON_LIB=libcJSON.a -lm
JSON_INCLUDE=-I./${EXTERNAL_JSON} 

cjson_c= ${EXTERNAL_JSON}cJSON.c
cjson_o = $(cjson_c:.c=.o)

${EXTERNAL_JSON}%.o: ${EXTERNAL_JSON}%.c
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@



libcJSON.a: ${cjson_o} 
	${OSSEC_LINK} $@ $^


####################
#### OSSEC Libs ####
####################

ossec_libs = config.a shared.a os_net.a \
						 os_regex.a os_xml.a os_crypto.a

#### os_xml ######## 
os_xml_c= $(wildcard os_xml/*.c)
os_xml_o = $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c 
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_xml.a: ${os_xml_o} 
	${OSSEC_LINK} os_xml.a $^


#### os_regex ######

os_regex_c= $(wildcard os_regex/*.c)
os_regex_o = $(os_regex_c:.c=.o)

os_regex/%.o: os_regex/%.c 
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_regex.a: ${os_regex_o}
	${OSSEC_LINK} os_regex.a $^

#### os_net ##########

os_net_c = $(wildcard os_net/*.c)
os_net_o = $(os_net_c:.c=.o)

os_net/%.o: os_net/%.c 
	${OSSEC_CC} ${CFLAGS} -c $^ -o $@

os_net.a: ${os_net_o}
	${OSSEC_LINK} os_net.a $^ 

#### Shared ##########

shared_c = $(wildcard shared/*.c)
shared_o = $(shared_c:.c=.o)

shared/%.o: shared/%.c 
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"shared-libs\" -c $^ -o $@

shared.a: ${shared_o}
	${OSSEC_LINK} shared.a $^ 

#### Config ########## 

config_c = $(wildcard config/*.c)
config_o = $(config_c:.c=.o)

config/%.o: config/%.c 
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"config-libs\" -c $^ -o $@

config.a: ${config_o}
	${OSSEC_LINK} $@ $^ 

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

crypto_shared_c = $(wildcard os_crypto/shared/*.c)
crypto_shared_o = $(crypto_shared_c:.c=.o)

os_crypto/shared/%.o: os_crypto/shared/%.c
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"crypto\" -c $^ -o $@


crypto_o = ${crypto_blowfish_o} \
					 ${crypto_md5_o} \
					 ${crypto_sha1_o} \
					 ${crypto_shared_o}

os_crypto.a: ${crypto_o}
	${OSSEC_LINK} $@ $^


#### os_mail #########

os_maild_c = $(wildcard os_maild/*.c)
os_maild_o = $(os_maild_c:.c=.o)

os_maild/%.o: os_maild/%.c 
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-maild\" -c $^ -o $@

ossec-maild: ${ossec_libs} ${os_maild_o} 
	${OSSEC_CC} ${CFLAGS} ${IEXTRA} ${os_maild_o} ${ossec_libs} -o $@

#### os_dbd ########## 

#### os_csyslogd #####

os_csyslogd_c = $(wildcard os_csyslogd/*.c)
os_csyslogd_o = $(os_csyslogd_c:.c=.o)

os_csyslogd/%.o: os_csyslogd/%.c 
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} -DARGV0=\"ossec-csyslogd\" -c $^ -o $@

ossec-csyslogd: ${ossec_libs} ${os_csyslogd_o} ${JSON_LIB}
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} ${IEXTRA} ${os_csyslogd_o} ${JSON_LIB} ${ossec_libs} -o $@


#### agentlessd ####

os_agentlessd_c = $(wildcard agentlessd/*.c)
os_agentlessd_o = $(os_agentlessd_c:.c=.o)

agentlessd/%.o: agentlessd/%.c 
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-agentlessd\" -c $^ -o $@

ossec-agentlessd: ${ossec_libs} ${os_agentlessd_o} 
	${OSSEC_CC} ${CFLAGS} ${IEXTRA} ${os_agentlessd_o} ${ossec_libs} -o $@

#### os_execd #####

os_execd_c = $(wildcard os_execd/*.c)
os_execd_o = $(os_execd_c:.c=.o)

os_execd/%.o: os_execd/%.c 
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-execd\" -c $^ -o $@

ossec-execd: ${ossec_libs} ${os_execd_o} ${JSON_LIB}
	${OSSEC_CC} ${CFLAGS} ${JSON_INCLUDE} ${IEXTRA} ${os_execd_o} ${JSON_LIB} ${ossec_libs} -o $@


#### logcollectord ####

os_logcollector_c = $(wildcard logcollector/*.c)
os_logcollector_o = $(os_logcollector_c:.c=.o)

logcollector/%.o: logcollector/%.c 
	${OSSEC_CC} ${CFLAGS} -DARGV0=\"ossec-logcollector\" -c $^ -o $@

ossec-logcollector: ${ossec_libs} ${os_logcollector_o} 
	${OSSEC_CC} ${CFLAGS} ${IEXTRA} ${os_logcollector_o} ${ossec_libs} -o $@

#### os_mail #########

remoted_c = $(wildcard remoted/*.c)
remoted_o = $(remoted_c:.c=.o)

remoted/%.o: remoted/%.c 
	${OSSEC_CC} ${CFLAGS} -I./remoted -DARGV0=\"ossec-remoted\" -c $^ -o $@

ossec-remoted: ${ossec_libs} ${remoted_o} 
	${OSSEC_CC} ${CFLAGS} ${IEXTRA} ${remoted_o} ${ossec_libs} ${TEXTRA} -lpthread -o $@



####################
#### test ########## 
####################

test: all 
		cd tests/ && make 

check: test 

####################
#### Clean ######### 
####################

clean:  clean-test clean-interals clean-external 

clean-test: 
		cd tests/ && make clean 

clean-external:
	rm -f ${cjson_o} libcJSON.a
	cd external && make clean
	cd ${EXTERNAL_LUA} && make clean


clean-interals: 
	rm -f ${os_xml_o} os_xml.a 
	rm -f ${os_regex_o} os_regex.a 
	rm -f ${os_net_o} os_net.a 
	rm -f ${shared_o} shared.a 
	rm -f ${config_o} config.a 
	rm -f ${os_maild_o} ossec-maild
	rm -f ${crypto_o}  os_crypto.a
	rm -f ${os_csyslogd_o} ossec-csyslogd 
	rm -f ${os_agentlessd_o} ossec-agentlessd
	rm -f ${os_execd_o} ossec-execd
	rm -f ${os_logcollector_o} ossec-logcollector
	rm -f ${remoted_o} ossec-remoted




