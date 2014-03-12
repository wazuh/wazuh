# Config.Make
# Options for the Makefile
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net


include ${PT}LOCATION
include ${PT}Config.OS

CC?=cc
CFLAGS = -g -Wall -I${PT} -I${PT}headers ${CPATH} ${CEXTRA} ${DEXTRA} ${EEXTRA} ${FEXTRA} ${GEXTRA} ${HEXTRA} ${MEXTRA} ${CGEOIP} -DARGV0=\"${NAME}\" -DOSSECHIDS

SOURCES = *.c
OBJECTS = *.o
CLEAN = rm -f -r ${OBJECTS} ${NAME} *.a core core.* *.core *.gcda *.gcno
BUILD = cp -pr ${NAME} ${PT}../bin
BUILDLIB = ar -crus

OS_XML = ${PT}os_xml/os_xml.a
OS_REGEX = ${PT}os_regex/os_regex.a
OS_NET = ${PT}os_net/os_net.a
OS_CRYPTO = ${PT}os_crypto/os_crypto.a
OS_SHARED = ${PT}shared/lib_shared.a
OS_ROOTCHECK = ${PT}rootcheck/rootcheck_lib.a
OS_CONFIG = ${PT}config/lib_config.a
OS_ZLIB = ${PT}os_zlib/os_zlib.c ${PT}external/libz.a
OS_LINK = ${IEXTRA}
OS_CJSON = ${PT}external/libcJSON.a -lm
DBS = cdb/cdb.a
