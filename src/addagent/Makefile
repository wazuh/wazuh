# Makefile for addagent
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

NAME=addagent
PT=../

include $(PT)Config.Make

OBJS = ${OS_SHARED} ${OS_REGEX} ${OS_CRYPTO}

$(NAME):
		$(CC) -DARGV0=\"$(NAME)\" $(CFLAGS) addagent.c $(OBJS) -o $@
		$(CC) $(CFLAGS) manage_agents.c b64.c $(OBJS) -o manage_agents
clean:
		$(CLEAN) manage_agents
build:
		${BUILD} 
		cp -pr manage_agents ${PT}../bin
