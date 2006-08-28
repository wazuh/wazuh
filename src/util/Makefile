# Makefile for util.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=util

SUP=../addagent/manage_agents.c ../addagent/manage_keys.c ../addagent/validate.c ../addagent/read_from_user.c ../addagent/b64.c
include $(PT)Config.Make

OBJS = ${OS_ZLIB} ${OS_SHARED} ${OS_REGEX} ${OS_CRYPTO}

me:
		$(CC) $(CFLAGS) ${SUP} syscheck_update.c $(OBJS) -o syscheck_update
		$(CC) $(CFLAGS) clear_stats.c $(OBJS) -o clear_stats
		$(CC) $(CFLAGS) list_agents.c $(OBJS) -o list_agents
clean:
		$(CLEAN) syscheck_update clear_stats list_agents
build:
		cp -pr syscheck_update clear_stats list_agents ${PT}../bin
