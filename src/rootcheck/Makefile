# Makefile for OSSEC rootcheck
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/
# http://www.ossec.net/rootcheck/

PT=../
NAME=ossec-rootcheck

include ../Config.Make


OBJS = *.c ${OS_SHARED} ${OS_XML}

rootcheck:
		$(CC) $(CFLAGS) -c *.c -D_GNU_SOURCE
		ar cru rootcheck_lib.a *.o
		ranlib rootcheck_lib.a
        
binary:        
		$(CC) $(CFLAGS) $(OBJS) -U OSSECHIDS -D_GNU_SOURCE -o ${NAME}
clean:
		${CLEAN} rootcheck_lib.a
build:
		-${BUILD}
