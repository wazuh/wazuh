# Makefile -- shared functions
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

NAME=shared-libs
PT=../

include ../Config.Make

lib_shared.a: ${SOURCES}
		${CC} -c ${CFLAGS} ${SOURCES}
		${BUILDLIB} lib_shared.a ${OBJECTS}

clean:
		${CLEAN}
