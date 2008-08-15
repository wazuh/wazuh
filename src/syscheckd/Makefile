# Makefile for OSSEC syscheckd
# Daniel B. Cid <dcid @ ossec.net>
# http://www.ossec.net

PT=../
NAME=ossec-syscheckd

include ../Config.Make


OBJS = syscheck.c config.c create_db.c run_check.c ${OS_CONFIG} ${OS_ROOTCHECK} ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_CRYPTO}
OBJS2 = syscheck-baseline.c config.c create_db.c run_check.c ${OS_CONFIG} ${OS_ROOTCHECK} ${OS_SHARED} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_CRYPTO}

syscheck:
		$(CC) $(CFLAGS) ${OS_LINK} $(OBJS) -o ${NAME}
        
baseline:
		$(CC) $(CFLAGS) ${OS_LINK} $(OBJS2) -o syscheck-baseline
        
clean:
		${CLEAN}
build:
		${BUILD}
