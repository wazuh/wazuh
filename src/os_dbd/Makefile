# Makefile for dbd
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-dbd
DBFLAGS=-I/usr/local/include/mysql -L/usr/local/lib/mysql -lmysqlclient

include ../Config.Make

LOCAL = *.c

OBJS = ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML}

dbd:
		${CC} ${CFLAGS} ${DBFLAGS} -DDBD -DUMYSQL ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
