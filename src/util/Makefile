# Makefile for util.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=util

SUP=../addagent/manage_agents.c ../addagent/manage_keys.c ../addagent/validate.c ../addagent/read_from_user.c ../addagent/b64.c
include $(PT)Config.Make

OBJS = ${OS_ZLIB} ${OS_CRYPTO} ${OS_SHARED} ${OS_REGEX} ${OS_NET}

top: syscheck_update clear_stats list_agents agent_control syscheck_control rootcheck_control verify-agent-conf ossec-regex 

syscheck_update: syscheck_update.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} syscheck_update.c $(OBJS) -o syscheck_update

clear_stats: clear_stats.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} clear_stats.c $(OBJS) -o clear_stats

list_agents: list_agents.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} list_agents.c $(OBJS) -o list_agents

verify-agent-conf: verify-agent-conf.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} verify-agent-conf.c $(OS_CONFIG) $(OBJS) ${OS_XML} -o verify-agent-conf

agent_control: agent_control.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} agent_control.c $(OBJS) -o agent_control

syscheck_control: syscheck_control.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} syscheck_control.c $(OBJS) -o syscheck_control

rootcheck_control: rootcheck_control.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} ${SUP} rootcheck_control.c $(OBJS) -o rootcheck_control

ossec-regex: ossec-regex.c ${OBJS}
		$(CC) $(CFLAGS) ${OS_LINK} ossec-regex.c $(OBJS) -o ossec-regex 


clean:
		$(CLEAN) syscheck_update clear_stats list_agents agent_control syscheck_control rootcheck_control verify-agent-conf ossec-regex 
build:
		cp -pr syscheck_update clear_stats list_agents syscheck_control rootcheck_control agent_control verify-agent-conf ossec-regex ${PT}../bin
