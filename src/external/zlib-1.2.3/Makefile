# Makefile for zlib.
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

NAME=zlib
PT=../../

include ${PT}Config.Make

libz.a:
		${CC} ${CFLAGS} -c ${SOURCES}
		${BUILDLIB} libz.a ${OBJECTS}
clean:
		${CLEAN} ../../headers/zlib.h ../../headers/zconf.h ../libz.a

ossec: libz.a
		cp -pr zlib.h zconf.h ../../headers/
		cp -pr libz.a ../
