# Makefile for logcollector
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-logcollector

include ../Config.Make


logr_OBJS = logcollector.c config.c read_snortfull.c read_syslog.c  ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET}

logcollector:
		${CC} ${CFLAGS} -DARGV0=\"${NAME}\" ${logr_OBJS} -o ${NAME}

clean:
		${CLEAN}
build:
		${BUILD}
