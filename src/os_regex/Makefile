# Makefile for os_regex
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=os_regex

include ../Config.Make

os_regex.a: *.c *.h
		${CC} ${CFLAGS} -c ${SOURCES}
		${BUILDLIB} os_regex.a ${OBJECTS}

clean:
		${CLEAN}
