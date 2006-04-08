# Makefile for the configuration check.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net

PT=../
NAME=ossec-config

include ../Config.Make


SOURCES = *.c

logcollector:
		${CC} -c ${CFLAGS} ${SOURCES}
		ar cru lib_config.a ${OBJECTS}
		ranlib lib_config.a

clean:
		${CLEAN}
build:
		${BUILD}
