

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_S := $(shell sh -c ' 2>/dev/null || echo not')



BUILDLIB=ar -crus


EXTERNAL_JSON="external/cJSON/"
EXTERNAL_LUA="external/lua/"
LUA_PLAT="posix"
MAX=2048
DEFINES=-DMAX_AGENTS=${MAX}

ifeq ($(uname_S),Linux)
		DEFINES+=-DUSEINOTIFY
		DEFINES+=-DUSE_MAGIC
		LIB_MAGIC="-lmagic"
else 
ifeq ($(uname_S),AIX)
		DEFINES+=-DAIX
		DEFINES+=-DHIGHFIRST
		PATH=${PATH}:/usr/vac/bin

else 
ifeq ($(uname_S),SunOS)
		DEFINES+=-DSOLARIS
		DEFINES+=-DHIGHFIRST
		IEXTRA="-lsocket -lnsl -lresolv"
		LUA_PLAT="solaris"

else 
ifeq ($(uname_S),Darwin)
		DEFINES+=-DDarwin
		DEFINES+=-DHIGHFIRST
		LUA_PLAT="macosx"

else 
ifeq ($(uname_S),FreeBSD)
		DEFINES+=-DFreeBSD
		TEXTRA="-pthread"
		LUA_PLAT="freebsd"
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

all: deps ossec-maild

####################
#### External ###### 
####################

deps:
	cd ${EXTERNAL_JSON} && make ossec 
	cd external && make zlib
	cd ${EXTERNAL_LUA} && make ${LUA_PLAT} 


####################
#### OSSEC Libs 
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

crypto_c = $(wildcard os_crypto/blowfish/*.c)
crypto_c += $(wildcard os_crypto/md5/*.c)
crypto_c += $(wildcard os_crypto/sha1/*.c)
crypto_c += $(wildcard os_crypto/shared/*.c)
crypto_c = $(filter-out main.c)

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

crypto_o = ${crypto_blowfish_o} ${crypto_md5_o} \
					 ${crypto_blowfish_o}

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
		cd ${EXTERNAL_JSON} && make clean
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




