# Makefile for addagent /manage_agents
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

NAME=manage_agents
PT=../

include $(PT)Config.Make

OBJS = ${OS_SHARED} ${OS_REGEX} ${OS_ZLIB} ${OS_CRYPTO} ${OS_NET}

${NAME}: *.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} *.c $(OBJS) -o manage_agents
clean:
		$(CLEAN) manage_agents
build:
		${BUILD} 
		cp -pr manage_agents ${PT}../bin
