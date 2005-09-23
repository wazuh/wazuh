# Makefile for OSSEC agent
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-agentd

include ../Config.Make


clog_OBJS = agentd.c config.c ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_CRYPTO}

agent:
		$(CC) $(CFLAGS) $(clog_OBJS) -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
