# Makefile for maild
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=ossec-execd

include ../Config.Make

LOCAL = execd.c config.c os_execd_client.c exec.c

OBJS = ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML}

addclient:
		${CC} ${CFLAGS} ${LOCAL} ${OBJS} -o ${NAME}
		${CC} ${CFLAGS} -c ${LOCAL}
clean:
		${CLEAN}
build:
		${BUILD}
