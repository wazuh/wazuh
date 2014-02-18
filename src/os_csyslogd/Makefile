# Makefile for client-syslog
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-csyslogd


include ../Config.Make
LOCAL = *.c


OBJS = ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML} ${OS_CJSON}

default:
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
