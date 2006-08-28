# Makefile for monitord 
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-monitord

include ../Config.Make

LOCAL = *.c

OBJS = ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_ZLIB}

mmonitor:
		${CC} ${CFLAGS} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
