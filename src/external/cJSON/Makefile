# Makefile for zlib.
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

NAME=cJSON
PT=../../

include ${PT}Config.Make

shared:
		${CC} -c ${CFLAGS} ${SOURCES}
		ar cru libcJSON.a ${OBJECTS}
		ranlib libcJSON.a
clean:
		${CLEAN} ../../headers/cJSON.h ../libcJSON.a

ossec:
		cp -pr cJSON.h ../../headers/
		cp -pr libcJSON.a ../
