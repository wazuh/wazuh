# Makefile for cJSON.
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

NAME=cJSON
PT=../../

include ${PT}Config.Make

libcJSON.a: cJSON.h cJSON.c
		${CC} ${CFLAGS} -c cJSON.c
		${BUILDLIB} libcJSON.a ${OBJECTS}
		
clean:
		${CLEAN} ../../headers/cJSON.h ../libcJSON.a

ossec: libcJSON.a
		cp -pr cJSON.h ../../headers/
		cp -pr libcJSON.a ../
