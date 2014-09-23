# Makefile for monitord 
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-monitord

include ../Config.Make

LOCAL = compress_log.c main.c manage_files.c monitor_agents.c monitord.c sign_log.c generate_reports.c ../os_maild/sendcustomemail.c

OBJS = ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML} ${OS_CRYPTO} ${OS_ZLIB}

${NAME}: ${LOCAL} 
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}

build:
		${BUILD}
