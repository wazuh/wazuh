# Config.Make
# Options for the Makefile
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/


include ${PT}LOCATION
include ${PT}Config.OS


CFLAGS = -g -Wall -I${PT} -I${PT}headers ${CPATH} ${CEXTRA} ${DEXTRA} ${EEXTRA} -DARGV0=\"${NAME}\" -DXML_VAR=\"var\" -DOSSECHIDS

SOURCES = *.c
OBJECTS = *.o
CLEAN = rm -f -r ${OBJECTS} ${NAME} *.a core core.* *.core
BUILD = cp -pr ${NAME} ${PT}../bin

OS_XML = ${PT}os_xml/os_xml.a
OS_REGEX = ${PT}os_regex/os_regex.a
OS_NET = ${PT}os_net/os_net.a
OS_CRYPTO = ${PT}os_crypto/os_crypto.a
OS_SHARED = ${PT}shared/lib_shared.a
OS_ROOTCHECK = ${PT}rootcheck/rootcheck_lib.a
OS_CONFIG = ${PT}config/*.c
OS_ZLIB = ${PT}os_zlib/os_zlib.c ${PT}external/libz.a
