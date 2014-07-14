# Makefile for os_crypto shared
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>

PT=../../
NAME=shared

include ../../Config.Make

SRCS = *.c
OBJS = *.o


shared.a: ${SRCS}
		${CC} ${CFLAGS} -c ${SRCS}
		${BUILDLIB} shared.a ${OBJS}

clean:
		${CLEAN}
