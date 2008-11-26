# Makefile for monitord 
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-monitord

include ../Config.Make

LOCAL = compress_log.c main.c manage_files.c monitor_agents.c monitord.c sign_log.c

OBJS = ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_CRYPTO} ${OS_ZLIB}

mmonitor:
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
		${CC} ${CFLAGS} ${OS_LINK} -UARGV0 -DARGV0=\"ossec-reportd\" report.c ${OBJS} -o ossec-reportd
clean:
		${CLEAN}
		rm -f ossec-reportd
build:
		${BUILD}
		cp -pr ossec-reportd ${PT}../bin
