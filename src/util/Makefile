# Makefile for util.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=util

SUP=../addagent/manage_agents.c ../addagent/manage_keys.c ../addagent/validate.c ../addagent/read_from_user.c ../addagent/b64.c
include $(PT)Config.Make

OBJS = ${OS_ZLIB} ${OS_CRYPTO} ${OS_SHARED} ${OS_REGEX} ${OS_NET}

me:
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} syscheck_update.c $(OBJS) -o syscheck_update
		$(CC) $(CFLAGS) ${OS_LINK} clear_stats.c $(OBJS) -o clear_stats
		$(CC) $(CFLAGS) ${OS_LINK} list_agents.c $(OBJS) -o list_agents
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} agent_control.c $(OBJS) -o agent_control
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} syscheck_control.c $(OBJS) -o syscheck_control
clean:
		$(CLEAN) syscheck_update clear_stats list_agents agent_control
build:
		cp -pr syscheck_update clear_stats list_agents syscheck_control agent_control ${PT}../bin
