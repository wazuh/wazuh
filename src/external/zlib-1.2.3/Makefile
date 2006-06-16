# Makefile -- shared functions
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

NAME=zlib
PT=../../

include ${PT}Config.Make

shared:
		${CC} -c ${CFLAGS} ${SOURCES}
		ar cru libz.a ${OBJECTS}
		ranlib libz.a
clean:
		${CLEAN} ../../headers/zlib.h ../libz.a

ossec:
		cp -pr zlib.h ../../headers
		cp -pr libz.a ../
