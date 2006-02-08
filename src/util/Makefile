# Makefile for util.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../

ADDAGENT=../addagent/manage_agents.c ../addagent/manage_keys.c ../addagent/validate.c ../addagent/read_from_user.c ../addagent/b64.c
include $(PT)Config.Make

OBJS = ${OS_SHARED} ${OS_REGEX} ${OS_CRYPTO}

me:
		$(CC) $(CFLAGS) ${ADDAGENT} syscheck_update.c $(OBJS) -o syscheck_update
clean:
		$(CLEAN) syscheck_update
build:
		cp -pr syscheck_update  ${PT}../bin
