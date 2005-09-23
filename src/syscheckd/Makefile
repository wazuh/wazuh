# Makefile for OSSEC syscheckd
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/
# http://www.ossec.net/syscheck/

PT=../
NAME=ossec-syscheckd

include ../Config.Make


OBJS = syscheck.c config.c create_db.c run_check.c ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_CRYPTO}

syscheck:
		$(CC) $(CFLAGS) $(OBJS) -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
