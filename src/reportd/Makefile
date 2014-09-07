# Makefile for reportd 
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-reportd

include ${PT}/Config.Make

LIBS = ${OS_SHARED} ${OS_REGEX}

ossec-reportd: report.c ${LIBS}
		${CC} ${CFLAGS} ${OS_LINK} report.c ${LIBS} -o $@

clean:
		${CLEAN}

build: ossec-reportd
		${BUILD}
