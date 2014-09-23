# Makefile for OSSEC rootcheck
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/
# http://www.ossec.net/rootcheck/

PT=../
NAME=ossec-rootcheck

include ../Config.Make


OBJS = check_open_ports.c check_rc_pids.c check_rc_trojans.c run_rk_check.c check_rc_dev.c check_rc_ports.c check_rc_policy.c common.c common_rcl.c win-common.c unix-process.c check_rc_files.c check_rc_readproc.c os_string.c check_rc_if.c check_rc_sys.c rootcheck.c
OBJS2 = ${OS_SHARED} ${OS_XML} ${OS_REGEX}


${NAME}: rootcheck_lib.a ${OSJS}
		$(CC) $(CFLAGS) ${OS_LINK} ${OBJS} rootcheck-config.c ${OBJS2} -UOSSECHIDS -D_GNU_SOURCE -o ${NAME}

rootcheck_lib.a:
		$(CC) $(CFLAGS) -c ${OBJS} config.c -D_GNU_SOURCE
		ar cru rootcheck_lib.a *.o
		ranlib rootcheck_lib.a
        

clean:
		${CLEAN} rootcheck_lib.a

build:        
