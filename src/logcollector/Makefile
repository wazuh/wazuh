# Makefile for logcollector
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-logcollector

include ../Config.Make


logr_OBJS = *.c  ${OS_CONFIG} ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_CRYPTO} 

${NAME}:
		${CC} ${CFLAGS} ${OS_LINK} -DARGV0=\"${NAME}\" ${logr_OBJS} -o ${NAME}

clean:
		${CLEAN}
build:
		${BUILD}
