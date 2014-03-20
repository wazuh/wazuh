# Makefile for os_xml
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT = ../
NAME = os_xml

include ../Config.Make

os_xml.a: *.c *.h
		${CC} ${CFLAGS} -c ${SOURCES}
		${BUILDLIB} os_xml.a ${OBJECTS}

clean:
		${CLEAN}
