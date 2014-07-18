# Makefile for the configuration check.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net

PT=../
NAME=ossec-config

include ../Config.Make

lib_config.a: ${SOURCES} *.h
		${CC} -c ${CFLAGS} ${SOURCES}
		${BUILDLIB} lib_config.a ${OBJECTS}

clean:
		${CLEAN}
