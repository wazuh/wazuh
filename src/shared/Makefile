# Makefile -- shared functions
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

NAME=shared
PT=../

include ../Config.Make

shared:
		${CC} -c ${CFLAGS} ${SOURCES}
		ar cru lib_shared.a ${OBJECTS}
		ranlib lib_shared.a
clean:
		${CLEAN}
