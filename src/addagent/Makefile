# Makefile for addagent /manage_agents
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

NAME=manage_agents
PT=../

include $(PT)Config.Make

OBJS = ${OS_SHARED} ${OS_REGEX} ${OS_ZLIB} ${OS_CRYPTO}

handler:
		$(CC) $(CFLAGS) *.c $(OBJS) -o manage_agents
clean:
		$(CLEAN) manage_agents
build:
		${BUILD} 
		cp -pr manage_agents ${PT}../bin
