# Makefile for os_zlib tests.
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

PT=../
include ${PT}Config.Make

OBJS = ${OS_ZLIB}

zlib-test:
		${CC} ${CFLAGS} zlib-test.c ${OBJS} -o zlib-test
clean:
		${CLEAN} zlib-test
