# Makefile for agentlessd 
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-agentlessd

include ../Config.Make

LOCAL = *.c

OBJS =  ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML} ${OS_CRYPTO}

${NAME}: ${LOCAL} ${OBJS}
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
