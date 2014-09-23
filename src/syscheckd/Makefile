# Makefile for OSSEC syscheckd
# Daniel B. Cid <dcid @ ossec.net>
# http://www.ossec.net

PT=../
NAME=ossec-syscheckd

include ../Config.Make


OBJS = syscheck.c config.c seechanges.c run_realtime.c create_db.c run_check.c ${OS_CONFIG} ${OS_ROOTCHECK} ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_CRYPTO}

${NAME}:
		$(CC) $(CFLAGS) ${MAGICCMD} ${OS_LINK} $(OBJS) -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
