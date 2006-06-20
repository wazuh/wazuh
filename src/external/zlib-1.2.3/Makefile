# Makefile for zlib.
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

NAME=zlib
PT=../../

include ${PT}Config.Make

shared:
		${CC} -c ${CFLAGS} ${SOURCES}
		ar cru libz.a ${OBJECTS}
		ranlib libz.a
clean:
		${CLEAN} ../../headers/zlib.h ../../headers/zconf.h ../libz.a

ossec:
		cp -pr zlib.h zconf.h ../../headers/
		cp -pr libz.a ../
