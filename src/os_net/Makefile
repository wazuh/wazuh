# Makefile for os_net
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=os_net

include ../Config.Make

HEAD =  os_net.h
SRCS =  os_net.c
OBJS =  os_net.o

os_net.a: ${HEAD} ${SRCS}
		${CC} ${CFLAGS} -c ${SRCS}
		${BUILDLIB} os_net.a ${OBJS}

clean:
		${CLEAN}
