# Makefile for OSSEC agent
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-agentd

include ../Config.Make

LOCAL = *.c

clog_OBJS = ${LOCAL} ${OS_CONFIG} ${OS_ZLIB} ${OS_CRYPTO} ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} -DCLIENT

${NAME}: ${LOCAL}
		$(CC) $(CFLAGS) ${OS_LINK} $(clog_OBJS) -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
